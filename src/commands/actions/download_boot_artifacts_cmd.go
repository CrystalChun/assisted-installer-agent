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
	var req models.DownloadBootArtifactsRequest
	if err := json.Unmarshal([]byte(downloaderRequestStr), &req); err != nil {
		return fmt.Errorf("failed unmarshalling download boot artifacts request: %w", err)
	}

	bootFolder := path.Join(*req.HostFsMountDir, "/boot")
	if err := syscall.Mount(bootFolder, bootFolder, "", syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("failed remounting /host/boot folder as rw: %w", err)
	}

	// Attempt to cleanup ostree if the host is ostree-based
	// This is optional but can help free up space in /boot
	if err := cleanupOstreeIfNeeded(req); err != nil {
		log.Warnf("Ostree cleanup failed (non-critical): %v", err)
	}

	// Create temporary directory in /var (which has more space than /boot)
	// We'll download here first, then copy to /boot after cleanup
	varTempDir := path.Join(*req.HostFsMountDir, "/var/tmp/assisted-installer-boot-artifacts")
	if err := createFolderIfNotExist(varTempDir); err != nil {
		return fmt.Errorf("failed creating temp directory in /var: %w", err)
	}
	defer os.RemoveAll(varTempDir) // Clean up temp files

	httpClient, err := createHTTPClient(caCertPath)
	if err != nil {
		return fmt.Errorf("failed creating secure assisted service client: %w", err)
	}

	// Download to /var/tmp first (lots of space available)
	tmpKernelPath := path.Join(varTempDir, kernelFile)
	tmpInitrdPath := path.Join(varTempDir, initrdFile)

	log.Info("Downloading boot artifacts to temporary location in /var")
	if err := download(httpClient, tmpKernelPath, *req.KernelURL, retryDownloadAmount); err != nil {
		return fmt.Errorf("failed downloading kernel to temp location: %w", err)
	}

	if err := download(httpClient, tmpInitrdPath, *req.InitrdURL, retryDownloadAmount); err != nil {
		return fmt.Errorf("failed downloading initrd to temp location: %w", err)
	}
	log.Info("Successfully downloaded boot artifacts to temp location")

	// Now create final destination folders in /boot
	hostArtifactsFolder := path.Join(*req.HostFsMountDir, artifactsFolder)
	bootLoaderFolder := path.Join(*req.HostFsMountDir, "/boot/loader/entries")
	if err := createFolders(hostArtifactsFolder, bootLoaderFolder); err != nil {
		return fmt.Errorf("failed creating folders: %w", err)
	}

	// Copy files from /var/tmp to /boot/discovery
	finalKernelPath := path.Join(hostArtifactsFolder, kernelFile)
	finalInitrdPath := path.Join(hostArtifactsFolder, initrdFile)

	log.Info("Copying boot artifacts from /var to /boot/discovery")
	if err := copyFile(tmpKernelPath, finalKernelPath); err != nil {
		return fmt.Errorf("failed copying kernel to /boot: %w", err)
	}

	if err := copyFile(tmpInitrdPath, finalInitrdPath); err != nil {
		return fmt.Errorf("failed copying initrd to /boot: %w", err)
	}
	log.Info("Successfully copied boot artifacts to /boot/discovery")

	if err := createBootLoaderConfig(*req.RootfsURL, artifactsFolder, bootLoaderFolder); err != nil {
		return fmt.Errorf("failed creating bootloader config file on host: %w", err)
	}

	log.Infof("Successfully downloaded boot artifacts and created bootloader config.")
	log.Info("sleeping for 30 mins")
	time.Sleep(30 * time.Minute)
	log.Info("woke up from sleep")
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

func copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file %s: %w", src, err)
	}

	if err := os.WriteFile(dst, sourceData, 0644); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	log.Infof("Copied %s to %s", src, dst)
	return nil
}

// cleanupOstreeIfNeeded creates a script on the host and executes it via systemd-run
// This ensures the cleanup runs in native host context without container environment
func cleanupOstreeIfNeeded(req models.DownloadBootArtifactsRequest) error {
	log.Info("Attempting to cleanup ostree via systemd-run")

	// Create cleanup script on the host
	scriptPath := path.Join(*req.HostFsMountDir, "/var/ostree-cleanup.sh")
	scriptContent := `#!/bin/bash

# System is ostree-based, try rpm-ostree cleanup
echo "System is ostree-based, running rpm-ostree cleanup"
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

	// Clean up the script file
	os.Remove(scriptPath)

	if exitCode != 0 {
		log.Warnf("Ostree cleanup script failed: stdout=%s, stderr=%s", stdout, stderr)
		return fmt.Errorf("ostree cleanup script failed: %s", stderr)
	}

	log.Infof("Ostree cleanup completed successfully: %s", stdout)
	return nil
}
