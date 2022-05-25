// Code generated by mockery v1.0.0. DO NOT EDIT.

package util

import (
	net "net"

	mock "github.com/stretchr/testify/mock"
)

// MockInterface is an autogenerated mock type for the Interface type
type MockInterface struct {
	mock.Mock
}

// Addrs provides a mock function with given fields:
func (_m *MockInterface) Addrs() ([]net.Addr, error) {
	ret := _m.Called()

	var r0 []net.Addr
	if rf, ok := ret.Get(0).(func() []net.Addr); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]net.Addr)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Flags provides a mock function with given fields:
func (_m *MockInterface) Flags() net.Flags {
	ret := _m.Called()

	var r0 net.Flags
	if rf, ok := ret.Get(0).(func() net.Flags); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(net.Flags)
	}

	return r0
}

// HardwareAddr provides a mock function with given fields:
func (_m *MockInterface) HardwareAddr() net.HardwareAddr {
	ret := _m.Called()

	var r0 net.HardwareAddr
	if rf, ok := ret.Get(0).(func() net.HardwareAddr); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(net.HardwareAddr)
		}
	}

	return r0
}

// IsBonding provides a mock function with given fields:
func (_m *MockInterface) IsBonding() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsPhysical provides a mock function with given fields:
func (_m *MockInterface) IsPhysical() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsVlan provides a mock function with given fields:
func (_m *MockInterface) IsVlan() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MTU provides a mock function with given fields:
func (_m *MockInterface) MTU() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// Name provides a mock function with given fields:
func (_m *MockInterface) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// SpeedMbps provides a mock function with given fields:
func (_m *MockInterface) SpeedMbps() int64 {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	return r0
}

// Type provides a mock function with given fields:
func (_m *MockInterface) Type() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
