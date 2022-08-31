package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/types"
	"github.com/stretchr/testify/assert"
)

func TestGenerateNodeKey(t *testing.T) {
	ts := time.Date(2019, 9, 17, 20, 34, 58, 0, time.UTC)
	_hash := "4d42e1adfb9a4d3e1b02be5370b5d1668c49d970"
	nodekey := generateNodeKey("test", ts)
	assert.Equal(t, _hash, nodekey)
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
		RawEnrollment: enrollRaw,
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
