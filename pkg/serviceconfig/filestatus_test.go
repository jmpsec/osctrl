package serviceconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/config"
)

// setupFileTestDB mirrors setupTestDB but also migrates ConfigFileStatus.
func setupFileTestDB(t *testing.T) *ServiceConfigManager {
	t.Helper()
	db := setupTestDB(t)
	require.NoError(t, db.AutoMigrate(&ConfigFileStatus{}), "Failed to migrate file status schema")
	return &ServiceConfigManager{DB: db}
}

func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	writable := filepath.Join(dir, "tls.yml")
	require.NoError(t, os.WriteFile(writable, []byte("service: {}\n"), 0o644))

	ok, reason := CheckWritable(writable)
	assert.True(t, ok)
	assert.Empty(t, reason)

	readOnly := filepath.Join(dir, "readonly.yml")
	require.NoError(t, os.WriteFile(readOnly, []byte("service: {}\n"), 0o400))
	if os.Geteuid() == 0 {
		t.Log("running as root — skipping the read-only assertion, root ignores mode bits")
	} else {
		ok, reason = CheckWritable(readOnly)
		assert.False(t, ok)
		assert.Contains(t, reason, "permission denied")
	}

	ok, reason = CheckWritable(filepath.Join(dir, "missing.yml"))
	assert.False(t, ok)
	assert.NotEmpty(t, reason)

	ok, reason = CheckWritable("")
	assert.False(t, ok)
	assert.Contains(t, reason, "not started from a configuration file")
}

func TestReportFileUpserts(t *testing.T) {
	m := setupFileTestDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.yml")
	require.NoError(t, os.WriteFile(path, []byte("service: {}\n"), 0o644))

	require.NoError(t, m.ReportFile(config.ServiceTLS, path))
	status, err := m.GetFileStatus(config.ServiceTLS)
	require.NoError(t, err)
	assert.Equal(t, path, status.Path)
	assert.True(t, status.Writable)

	// A second boot must update the existing row, not add another.
	require.NoError(t, m.ReportFile(config.ServiceTLS, ""))
	status, err = m.GetFileStatus(config.ServiceTLS)
	require.NoError(t, err)
	assert.False(t, status.Writable)
	assert.NotEmpty(t, status.Reason)

	var count int64
	require.NoError(t, m.DB.Model(&ConfigFileStatus{}).Where("service = ?", config.ServiceTLS).Count(&count).Error)
	assert.EqualValues(t, 1, count)

	assert.Error(t, m.ReportFile("nonsense", path))
}

func TestHasPendingChanges(t *testing.T) {
	m := setupFileTestDB(t)
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), NoEnvironmentID))

	pending, err := m.HasPendingChanges(config.ServiceTLS, NoEnvironmentID)
	require.NoError(t, err)
	assert.False(t, pending, "freshly seeded config is identical to the file")

	_, err = m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"showBody":false}`, NoEnvironmentID)
	require.NoError(t, err)

	pending, err = m.HasPendingChanges(config.ServiceTLS, NoEnvironmentID)
	require.NoError(t, err)
	assert.True(t, pending, "a db-sourced section is a change the file does not have")

	// Another service must not see the TLS edit.
	pending, err = m.HasPendingChanges(config.ServiceAPI, NoEnvironmentID)
	require.NoError(t, err)
	assert.False(t, pending)
}

func TestPersistToFile(t *testing.T) {
	m := setupFileTestDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.yml")

	params := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, params, NoEnvironmentID))
	// Write a starting file so the config has something on disk to replace.
	require.NoError(t, config.GenerateTLSConfigFile(path, params, true))

	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"showBody":true}`, NoEnvironmentID)
	require.NoError(t, err)

	// A fresh struct, as the services pass in: persisting must not depend on
	// the caller having already resolved anything.
	require.NoError(t, m.PersistToFile(config.ServiceTLS, path, testTLSParams(), NoEnvironmentID))

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(written), "enableHttp: true", "db edit should be on disk")
	// Sections the operator never touched must survive the round trip —
	// persisting must not silently drop parts of the live config file.
	assert.Contains(t, string(written), "writerBatchSize: 50")
	assert.Contains(t, string(written), "enroll:", "rateLimits must not be dropped")

	// Once written, nothing is pending — otherwise the UI would keep
	// offering to write changes that are already on disk.
	pending, err := m.HasPendingChanges(config.ServiceTLS, NoEnvironmentID)
	require.NoError(t, err)
	assert.False(t, pending)

	section, err := m.GetSection(config.ServiceTLS, "debug", NoEnvironmentID)
	require.NoError(t, err)
	assert.Equal(t, SourceYAML, section.Source)
	var debug config.YAMLConfigurationDebug
	require.NoError(t, json.Unmarshal([]byte(section.Value), &debug))
	assert.True(t, debug.EnableHTTP, "the edited value must survive the source flip")
}

func TestPersistToFileNotWritable(t *testing.T) {
	m := setupFileTestDB(t)
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), NoEnvironmentID))

	err := m.PersistToFile(config.ServiceTLS, filepath.Join(t.TempDir(), "missing.yml"), testTLSParams(), NoEnvironmentID)
	assert.ErrorIs(t, err, ErrConfigFileNotWritable)
}

// TestPersistToFileLeavesLiveConfigAlone guards the reason PersistToFile takes
// a config argument at all: Resolve mutates what it is given, so a service
// passing its live ServiceParameters would silently apply pending edits to
// itself without the restart they are meant to go through.
func TestPersistToFileLeavesLiveConfigAlone(t *testing.T) {
	m := setupFileTestDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.yml")

	live := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, live, NoEnvironmentID))
	require.NoError(t, config.GenerateTLSConfigFile(path, live, true))

	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"showBody":true}`, NoEnvironmentID)
	require.NoError(t, err)
	require.NoError(t, m.PersistToFile(config.ServiceTLS, path, testTLSParams(), NoEnvironmentID))

	assert.False(t, live.Debug.EnableHTTP, "the running service's config must be untouched")
}
