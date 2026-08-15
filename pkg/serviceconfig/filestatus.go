package serviceconfig

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrConfigFileNotWritable is returned when a persist is attempted against a
// configuration file the service process cannot write.
var ErrConfigFileNotWritable = errors.New("configuration file is not writable")

// ConfigFileStatus records where a service's YAML configuration file lives
// and whether the process running that service can write to it.
//
// Each service reports its own row at boot. It cannot be reported centrally:
// osctrl-tls and osctrl-api run as separate processes, usually in separate
// containers with separate config volumes, so the API service can neither
// stat nor write the TLS service's file. The database is the only channel
// through which that fact travels — the same reason restarts are requested
// through pkg/servicecommands rather than performed directly.
type ConfigFileStatus struct {
	gorm.Model
	Service   string `gorm:"uniqueIndex"`
	Path      string
	Writable  bool
	Reason    string
	CheckedAt time.Time
}

// CheckWritable reports whether the current process can write the given
// configuration file, and a human-readable reason when it cannot.
//
// The check opens the file for writing without O_CREATE or O_TRUNC: that
// tests the permission the persist actually needs without touching the
// contents, and it is accurate where reasoning about mode bits, uid/gid and
// ACLs separately would not be.
func CheckWritable(path string) (bool, string) {
	if path == "" {
		return false, "service was not started from a configuration file"
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false, err.Error()
	}
	_ = f.Close()
	return true, ""
}

// ReportFile records this service's configuration file path and whether the
// running process can write it. Services call this at boot, alongside Seed.
func (m *ServiceConfigManager) ReportFile(service, path string) error {
	if !m.VerifyService(service) {
		return fmt.Errorf("unknown service %q", service)
	}
	writable, reason := CheckWritable(path)
	status := ConfigFileStatus{
		Service:   service,
		Path:      path,
		Writable:  writable,
		Reason:    reason,
		CheckedAt: time.Now(),
	}
	if err := m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "service"}},
		DoUpdates: clause.AssignmentColumns([]string{"path", "writable", "reason", "checked_at", "updated_at"}),
	}).Create(&status).Error; err != nil {
		return fmt.Errorf("report config file for %s: %w", service, err)
	}
	log.Debug().Msgf("Reported config file for %s: %s (writable=%t)", service, path, writable)
	return nil
}

// GetFileStatus retrieves the reported configuration file status of a service.
func (m *ServiceConfigManager) GetFileStatus(service string) (ConfigFileStatus, error) {
	var status ConfigFileStatus
	if err := m.DB.Where("service = ?", service).First(&status).Error; err != nil {
		return ConfigFileStatus{}, err
	}
	return status, nil
}

// HasPendingChanges reports whether any section of the service has been edited
// through the API and therefore no longer matches the YAML file on disk. A
// row with source=db is by definition a change the file does not have.
func (m *ServiceConfigManager) HasPendingChanges(service string, envID uint) (bool, error) {
	var count int64
	if err := m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND environment_id = ? AND source = ?", service, envID, SourceDB).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("count pending changes for %s: %w", service, err)
	}
	return count > 0, nil
}

// PersistToFile writes the effective configuration — the YAML file with the
// DB-edited sections overlaid — back to disk, then marks every section as
// being in sync with the file again.
//
// cfg must be a FRESH load of the YAML file, never the running service's live
// ServiceParameters: Resolve mutates what it is given, so passing the live
// struct would apply the operator's pending edits to the running service
// without the restart they are supposed to go through.
func (m *ServiceConfigManager) PersistToFile(service, path string, cfg *config.ServiceParameters, envID uint) error {
	if !m.VerifyService(service) {
		return fmt.Errorf("unknown service %q", service)
	}
	if cfg == nil {
		return fmt.Errorf("nil ServiceParameters for %s", service)
	}
	if writable, reason := CheckWritable(path); !writable {
		return fmt.Errorf("%w: %s", ErrConfigFileNotWritable, reason)
	}
	if err := m.Resolve(service, cfg, envID); err != nil {
		return fmt.Errorf("resolve before persist: %w", err)
	}
	var err error
	switch service {
	case config.ServiceTLS:
		err = config.GenerateTLSConfigFile(path, cfg, true)
	case config.ServiceAPI:
		err = config.GenerateAPIConfigFile(path, cfg, true)
	}
	if err != nil {
		return fmt.Errorf("write config file %s: %w", path, err)
	}
	// The file now matches the database, so every section is once again
	// sourced from YAML. Without this the UI would keep offering to write
	// changes that are already on disk.
	if err := m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND environment_id = ? AND source = ?", service, envID, SourceDB).
		Update("source", SourceYAML).Error; err != nil {
		return fmt.Errorf("reset source after persist %s: %w", service, err)
	}
	log.Info().Msgf("Persisted service config for %s to %s", service, path)
	return m.ReportFile(service, path)
}
