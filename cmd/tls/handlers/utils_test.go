package handlers

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Node keys authenticate agents, so they must not be derivable from the host
// identifier or the enrollment time.
func TestGenerateNodeKey(t *testing.T) {
	first := generateNodeKey()
	second := generateNodeKey()
	assert.Regexp(t, `^[0-9a-f]{64}$`, first)
	assert.NotEqual(t, first, second)
}

func TestGenerateCarveSessionID(t *testing.T) {
	first := generateCarveSessionID()
	second := generateCarveSessionID()
	assert.NotEqual(t, first, second)
}

func TestNodeFromEnroll(t *testing.T) {
	_env := environments.TLSEnvironment{
		Name: "environment",
	}
	_ip := "1.2.3.4"
	_key := "node-key"
	_rec := 12345
	req := types.EnrollRequest{
		EnrollSecret:   "secret",
		HostIdentifier: "thisistheuuid",
		PlatformType:   "platform_type",
	}
	req.HostDetails.EnrollOSVersion = types.OSVersionTable{
		ID:           "",
		Codename:     "",
		Major:        "",
		Minor:        "",
		Name:         "",
		Patch:        "",
		Platform:     "",
		PlatformLike: "",
		Version:      "",
	}
	req.HostDetails.EnrollOsqueryInfo = types.OsqueryInfoTable{
		BuildDistro:   "",
		BuildPlatform: "",
		ConfigHash:    "",
		ConfigValid:   "",
		Extension:     "",
		InstanceID:    "",
		PID:           "",
		StartTime:     "",
		UUID:          "",
		Version:       "",
		Watcher:       "",
	}
	req.HostDetails.EnrollSystemInfo = types.SystemInfoTable{
		ComputerName:     "",
		CPUBrand:         "",
		CPULogicalCores:  "",
		CPUPhysicalCores: "",
		CPUSubtype:       "",
		CPUType:          "",
		HardwareModel:    "",
		HardwareSerial:   "",
		HardwareVendor:   "",
		HardwareVersion:  "",
		Hostname:         "",
		LocalHostname:    "",
		PhysicalMemory:   "memory",
		UUID:             "",
	}
	req.HostDetails.EnrollPlatformInfo = types.PlatformInfoTable{
		Address:    "",
		Date:       "",
		Extra:      "",
		Revision:   "",
		Size:       "",
		Vendor:     "",
		Version:    "",
		VolumeSize: "",
	}
	enrollRaw, _ := json.Marshal(req)
	node := nodes.OsqueryNode{
		UUID:          "THISISTHEUUID",
		Environment:   _env.Name,
		IPAddress:     _ip,
		NodeKey:       _key,
		Username:      "unknown",
		OsqueryUser:   "unknown",
		Memory:        "memory",
		BytesReceived: _rec,
		RawEnrollment: string(enrollRaw),
		UserID:        0,
		EnvironmentID: _env.ID,
	}
	resultNode := nodeFromEnroll(req, _env, _ip, _key, _rec)
	assert.Equal(t, node, resultNode)
}

func TestUniq(t *testing.T) {
	aa := uniq([]string{"a", "a", "b", "b", "b", "c"})
	bb := []string{"a", "b", "c"}
	assert.Equal(t, bb, aa)
}

func TestPackageFilename(t *testing.T) {
	aa := genPackageFilename("test", "1.2.3", "3.2.1", "msi")
	bb := "osctrl-test-1.2.3-osquery-3.2.1.msi"
	assert.Equal(t, bb, aa)
}
