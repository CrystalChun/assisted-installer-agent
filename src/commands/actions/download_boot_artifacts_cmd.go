package actions

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/openshift/assisted-installer-agent/src/config"
	"github.com/openshift/assisted-installer-agent/src/util"
	"github.com/openshift/assisted-service/models"
	log "github.com/sirupsen/logrus"
)

type downloadBootArtifacts struct {
	args        []string
	agentConfig *config.AgentConfig
}

func (a *downloadBootArtifacts) Validate() error {
	return ValidateCommon("download boot artifacts", 1, a.args, &models.DownloadBootArtifactsRequest{})
}

func (a *downloadBootArtifacts) Run() (stdout, stderr string, exitCode int) {
	err := run(a.agentConfig.InfraEnvID, a.Args()[0], a.agentConfig.CACertificatePath)
	if err != nil {
		return "", err.Error(), -1
	}
	return "Successfully downloaded boot artifacts", "", 0
}

// Unused, but required as part of ActionInterface
func (a *downloadBootArtifacts) Command() string {
	return "download_boot_artifacts"
}

// Unused, but required as part of ActionInterface
func (a *downloadBootArtifacts) Args() []string {
	return a.args
}

const (
	retryDownloadAmount                  = 5
	defaultDownloadRetryDelay            = 1 * time.Minute
	artifactsFolder               string = "/boot/discovery"
	kernelFile                    string = "vmlinuz"
	initrdFile                    string = "initrd"
	bootLoaderConfigFileName      string = "/00-assisted-discovery.conf"
	bootLoaderConfigTemplateS390x string = `title Assisted Installer Discovery
version 999
options random.trust_cpu=on ai.ip_cfg_override=1 ignition.firstboot ignition.platform.id=metal coreos.live.rootfs_url=%s
linux %s
initrd %s`
	bootLoaderConfigTemplate string = `title Assisted Installer Discovery
version 999
options random.trust_cpu=on ignition.firstboot ignition.platform.id=metal 'coreos.live.rootfs_url=%s'
linux %s
initrd %s`
)

func run(infraEnvId, downloaderRequestStr, caCertPath string) error {
	defer func() {
		log.Info("sleeping for 30 mins")
		time.Sleep(30 * time.Minute)
		log.Info("woke up from sleep")
	}()
	var req models.DownloadBootArtifactsRequest
	if err := json.Unmarshal([]byte(downloaderRequestStr), &req); err != nil {
		return fmt.Errorf("failed unmarshalling download boot artifacts request: %w", err)
	}

	bootFolder := path.Join(*req.HostFsMountDir, "/boot")
	if err := syscall.Mount(bootFolder, bootFolder, "", syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("failed remounting /host/boot folder as rw: %w", err)
	}
	info, err := os.Stat(bootFolder)
	if err != nil {
		log.Warnf("failed to stat /host/boot folder: %v", err)
	}
	log.Infof("boot folder size: %d", info.Size())

	// Attempt to cleanup ostree if the host is ostree-based
	// This is optional but can help free up space in /boot
	if err := cleanupOstreeIfNeeded(req); err != nil {
		log.Warnf("Ostree cleanup failed (non-critical): %v", err)
	}

	info, err = os.Stat(bootFolder)
	if err != nil {
		log.Warnf("failed to stat /host/boot folder: %v", err)
	}
	log.Infof("boot folder size: %d", info.Size())

	log.Info("try to run rpm ostree cleanup")
	stdout, stderr, exitCode := util.ExecutePrivilegedWithPIDNoContainer("rpm-ostree", "cleanup", "--os=rhcos", "-r")
	if exitCode != 0 {
		log.Warnf("rpm-ostree cleanup failed: %s", stderr)
	}
	log.Infof("rpm-ostree cleanup completed successfully: %s", stdout)
	info, err = os.Stat(bootFolder)
	if err != nil {
		log.Warnf("failed to stat /host/boot folder: %v", err)
	}
	log.Infof("boot folder size: %d", info.Size())

	/* 	// Create backing directory in /var (which has more space than /boot)
	   	varBootArtifacts := path.Join(*req.HostFsMountDir, "/var/lib/assisted-installer/boot-artifacts")
	   	if err := createFolderIfNotExist(varBootArtifacts); err != nil {
	   		log.Warnf("failed creating backing directory in /var: %v", err)
	   	}
	*/
	// Create mount point in /boot
	hostArtifactsFolder := path.Join(*req.HostFsMountDir, artifactsFolder)
	if err := createFolderIfNotExist(hostArtifactsFolder); err != nil {
		log.Warnf("failed creating /boot/discovery: %v", err)
	}

	/* 	// Bind mount /var/lib/assisted-installer/boot-artifacts to /boot/discovery
	   	// This allows us to use /var's larger storage while keeping files accessible in /boot
	   	if err := syscall.Mount(varBootArtifacts, hostArtifactsFolder, "", syscall.MS_BIND, ""); err != nil {
	   		log.Warnf("failed bind mounting %s to %s: %v", varBootArtifacts, hostArtifactsFolder, err)
	   	} else {
	   		log.Infof("Successfully bind mounted %s to %s", varBootArtifacts, hostArtifactsFolder)

	   		// Make the bind mount persistent across reboots by adding to /etc/fstab
	   		if err := addToFstab(req); err != nil {
	   			log.Warnf("Failed to add bind mount to fstab (non-critical): %v", err)
	   		}
	   	} */
	bootLoaderFolder := path.Join(*req.HostFsMountDir, "/boot/loader/entries")
	if err := createFolderIfNotExist(bootLoaderFolder); err != nil {
		log.Warnf("failed creating bootloader folder: %v", err)
	}

	httpClient, err := createHTTPClient(caCertPath)
	if err != nil {
		return fmt.Errorf("failed creating secure assisted service client: %w", err)
	}

	// Download directly to /boot/discovery (which is bind mounted to /var)
	if err := download(httpClient, path.Join(hostArtifactsFolder, kernelFile), *req.KernelURL, retryDownloadAmount); err != nil {
		return fmt.Errorf("failed downloading kernel to host: %w", err)
	}

	if err := download(httpClient, path.Join(hostArtifactsFolder, initrdFile), *req.InitrdURL, retryDownloadAmount); err != nil {
		return fmt.Errorf("failed downloading initrd to host: %w", err)
	}

	if err := createBootLoaderConfig(*req.RootfsURL, artifactsFolder, bootLoaderFolder); err != nil {
		return fmt.Errorf("failed creating bootloader config file on host: %w", err)
	}

	log.Infof("Successfully downloaded boot artifacts and created bootloader config.")

	return nil
}

func createHTTPClient(caCertPath string) (*http.Client, error) {
	client := &http.Client{}
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open cert file %s, %s", caCertPath, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append cert %s, %s", caCertPath, err)
		}

		t := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		}
		client.Transport = t
	}
	return client, nil
}

func download(httpClient *http.Client, filePath, url string, retry int) error {
	var downloadErr error
	var res *http.Response
	for attempts := 0; attempts < retry; attempts++ {
		res, downloadErr = httpClient.Get(url)
		if downloadErr == nil && (res.StatusCode >= 200 && res.StatusCode < 300) {
			break
		}
		downloadErr = fmt.Errorf("failed downloading boot artifact from %s, status code received: %d, attempt %d/%d, download error: %w",
			url, res.StatusCode, attempts, retry, downloadErr)
		log.Warn(downloadErr.Error())
		time.Sleep(defaultDownloadRetryDelay)
	}

	if downloadErr != nil {
		return fmt.Errorf("failed getting %s: %w", url, downloadErr)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read body while getting url %s: %w", url, err)
	}
	err = os.WriteFile(filePath, body, 0644) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed writing file %s: %w", filePath, err)
	}
	return nil
}

func createBootLoaderConfig(rootfsUrl, artifactsPath, bootLoaderPath string) error {
	kernelPath := path.Join(artifactsPath, kernelFile)
	initrdPath := path.Join(artifactsPath, initrdFile)
	bootLoaderConfigFile := path.Join(bootLoaderPath, bootLoaderConfigFileName)
	var bootLoaderConfig string
	bootLoaderConfig = fmt.Sprintf(bootLoaderConfigTemplate, rootfsUrl, kernelPath, initrdPath)
	if runtime.GOARCH == "s390x" {
		bootLoaderConfig = fmt.Sprintf(bootLoaderConfigTemplateS390x, rootfsUrl, kernelPath, initrdPath)
	}

	if err := os.WriteFile(bootLoaderConfigFile, []byte(bootLoaderConfig), 0644); err != nil { //nolint:gosec
		return fmt.Errorf("failed writing bootloader config content to %s: %w", bootLoaderConfigFile, err)
	}
	return nil
}

func createFolderIfNotExist(folder string) error {
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return os.MkdirAll(folder, 0755)
	}
	return nil
}

func createFolders(artifactsPath, bootLoaderPath string) error {
	err := createFolderIfNotExist(artifactsPath)
	if err != nil {
		return fmt.Errorf("failed to create artifacts folder [%s]: %w", artifactsPath, err)
	}
	err = createFolderIfNotExist(bootLoaderPath)
	if err != nil {
		return fmt.Errorf("failed to create bootloader folder [%s]: %w", bootLoaderPath, err)
	}
	return nil
}

// addToFstab adds the bind mount entry to /etc/fstab for persistence across reboots
func addToFstab(req models.DownloadBootArtifactsRequest) error {
	fstabPath := path.Join(*req.HostFsMountDir, "/etc/fstab")

	// Read current fstab content
	fstabContent, err := os.ReadFile(fstabPath)
	if err != nil {
		return fmt.Errorf("failed to read fstab: %w", err)
	}

	// Check if entry already exists
	if strings.Contains(string(fstabContent), "/boot/discovery") {
		log.Info("Bind mount entry already exists in /etc/fstab")
		return nil
	}

	// Create fstab entry
	fstabEntry := "/var/lib/assisted-installer/boot-artifacts /boot/discovery none bind 0 0\n"

	// Append to fstab
	f, err := os.OpenFile(fstabPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open fstab for writing: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(fstabEntry); err != nil {
		return fmt.Errorf("failed to write to fstab: %w", err)
	}

	log.Info("Successfully added bind mount entry to /etc/fstab")
	return nil
}

// cleanupOstreeIfNeeded creates a script on the host and executes it
// This ensures the cleanup runs in native host context without container environment
func cleanupOstreeIfNeeded(req models.DownloadBootArtifactsRequest) error {
	log.Info("Attempting to cleanup ostree via systemd-run")

	// Create cleanup script on the host
	scriptPath := path.Join(*req.HostFsMountDir, "/var/ostree-cleanup.sh")
	scriptContent := `#!/bin/bash
unset container
mount -o remount,rw /sysroot || true
rpm-ostree cleanup -b --os=rhcos
if [ $? -ne 0 ]; then
    echo "rpm-ostree cleanup failed, trying again with -r"
    rpm-ostree cleanup -b --os=rhcos -r
	if [ $? -ne 0 ]; then
		echo "rpm-ostree cleanup failed, giving up"
		exit 1
	fi
fi
echo "Successfully cleaned up ostree deployments"
`

	// Write script to host filesystem
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write cleanup script to %s: %w", scriptPath, err)
	}
	log.Infof("Wrote cleanup script to %s", scriptPath)

	// Execute the script with ExecutePrivilegedWithPIDNoContainer
	// This removes the container environment variable before execution
	stdout, stderr, exitCode := util.ExecutePrivilegedWithPIDNoContainer("bash", scriptPath)

	if exitCode != 0 {
		log.Warnf("Ostree cleanup script failed: stdout=%s, stderr=%s", stdout, stderr)
		return fmt.Errorf("ostree cleanup script failed: %s", stderr)
	}

	log.Infof("Ostree cleanup completed successfully: %s", stdout)
	return nil
}
