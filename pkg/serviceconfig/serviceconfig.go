// Package serviceconfig persists the structured YAML configuration sections
// (logger, carver, SAML, OIDC, metrics, TLS, etc.) per service into the
// database. Each row holds one section as a JSON-encoded blob, mirroring the
// YAML structure so it can be round-tripped back to YAML or rendered in the
// frontend.
//
// Phase 1 is read-only: sections are seeded from the YAML file on first boot
// (create-if-missing) and served via GET endpoints. The YAML file remains the
// live source of truth. Phase 2 will allow editing editable sections from the
// API, and phase 3 will let services consume the DB values at startup so the
// YAML can shrink to connection-only settings.
package serviceconfig

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SourceYAML marks a row seeded from the YAML file.
const SourceYAML string = "yaml"

// SourceDB marks a row that has been edited through the API.
const SourceDB string = "db"

// validServices mirrors pkg/settings.ValidServices. Duplicated here to
// avoid an import cycle (pkg/settings imports pkg/config, and this package
// also imports pkg/config; importing pkg/settings would be fine today but
// keeps the dependency graph clean if settings ever grows a dependency on
// serviceconfig).
var validServices = map[string]struct{}{
	config.ServiceTLS: {},
	config.ServiceAPI: {},
}

// ServiceConfig stores one YAML configuration section for a service.
type ServiceConfig struct {
	gorm.Model
	Name          string `gorm:"uniqueIndex:idx_service_config_unique"`
	Service       string `gorm:"uniqueIndex:idx_service_config_unique"`
	EnvironmentID uint   `gorm:"uniqueIndex:idx_service_config_unique"`
	Type          string // always "json" for now
	Value         string `gorm:"type:text"`
	Source        string // "yaml" or "db"
	Editable      bool
	Info          string
}

// ServiceConfigManager manages the service_config table.
type ServiceConfigManager struct {
	DB *gorm.DB
}

// SectionSpec describes one section in the registry.
type SectionSpec struct {
	Name     string
	Editable bool
	Info     string
}

// SectionRegistry maps each service to the sections it owns. The order
// of the slice defines the display order in the frontend. Sections marked
// Editable=false (db, redis, tls, saml, oidc, jwt, and other
// connection / secret / auth-bearing sections) can never be written through
// the API.
var SectionRegistry = map[string][]SectionSpec{
	config.ServiceTLS: {
		{"service", true, "Core service listener, port, log level, auth mode"},
		{"db", false, "Backend connection — not DB-editable"},
		{"batchWriter", true, "DB batch writer tuning"},
		{"redis", false, "Redis connection — not DB-editable"},
		{"osquery", true, "osquery feature toggles"},
		{"configEndpoints", false, "Config endpoint fan-out targets — contains secrets"},
		{"osctrld", true, "osctrld integration"},
		{"metrics", true, "Prometheus metrics endpoint"},
		{"tls", false, "TLS termination certificate/key paths — not DB-editable"},
		{"logger", false, "Log sinks — may contain credentials (future: editable)"},
		{"carver", false, "File carver configuration — may contain credentials"},
		{"debug", true, "HTTP debug dump settings"},
	},
	config.ServiceAPI: {
		{"service", true, "Core service listener, port, log level, auth mode"},
		{"db", false, "Backend connection — not DB-editable"},
		{"redis", false, "Redis connection — not DB-editable"},
		{"osquery", true, "osquery tables and feature toggles"},
		{"saml", false, "SAML federated login configuration — not DB-editable"},
		{"oidc", false, "OIDC federated login configuration — not DB-editable"},
		{"jwt", false, "JWT signing configuration — not DB-editable"},
		{"tls", false, "TLS termination certificate/key paths — not DB-editable"},
		{"logger", false, "Log sinks — may contain credentials (future: editable)"},
		{"carver", false, "File carver configuration — may contain credentials"},
		{"debug", true, "HTTP debug dump settings"},
	},
}

// NewServiceConfigManager initializes the manager and auto-migrates the
// service_config table.
func NewServiceConfigManager(backend *gorm.DB) *ServiceConfigManager {
	m := &ServiceConfigManager{DB: backend}
	if err := backend.AutoMigrate(&ServiceConfig{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (service_config): %v", err)
	}
	return m
}

// VerifyService checks that the service is one of the known services.
func (m *ServiceConfigManager) VerifyService(service string) bool {
	_, ok := validServices[service]
	return ok
}

// VerifySection checks that the section is registered for the given service.
func (m *ServiceConfigManager) VerifySection(service, section string) bool {
	for _, spec := range SectionRegistry[service] {
		if spec.Name == section {
			return true
		}
	}
	return false
}

// IsEditable checks that the section is registered and marked editable.
func (m *ServiceConfigManager) IsEditable(service, section string) bool {
	for _, spec := range SectionRegistry[service] {
		if spec.Name == section {
			return spec.Editable
		}
	}
	return false
}

// Seed persists all sections from the YAML-loaded ServiceParameters into the
// database using create-if-missing semantics. If a row already exists for a
// (service, section, envID) tuple it is left untouched — the YAML never
// overwrites a DB-edited value. This makes seeding idempotent and safe to run
// on every boot.
func (m *ServiceConfigManager) Seed(service string, cfg *config.ServiceParameters, envID uint) error {
	if !m.VerifyService(service) {
		return fmt.Errorf("unknown service %q", service)
	}
	if cfg == nil {
		return fmt.Errorf("nil ServiceParameters for %s", service)
	}
	values, err := sectionValues(service, cfg)
	if err != nil {
		return fmt.Errorf("marshal sections for %s: %w", service, err)
	}
	for _, spec := range SectionRegistry[service] {
		raw, ok := values[spec.Name]
		if !ok {
			continue
		}
		entry := ServiceConfig{
			Name:          spec.Name,
			Service:       service,
			EnvironmentID: envID,
			Type:          "json",
			Value:         raw,
			Source:        SourceYAML,
			Editable:      spec.Editable,
			Info:          spec.Info,
		}
		// ON CONFLICT DO NOTHING — create-if-missing. We use a unique
		// index on (service, name, environment_id, deleted_at) to guard
		// against duplicate seeds under concurrent boot. The clause.OnConflict
		// with DoNothing handles the SQLite/Postgres/MySQL cases GORM
		// supports.
		if err := m.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&entry).Error; err != nil {
			return fmt.Errorf("seed %s/%s: %w", service, spec.Name, err)
		}
		// Sync registry metadata (Editable, Info) to existing rows. These
		// are schema-level flags controlled by the code, not operator data,
		// so they must always reflect the current registry — even for rows
		// that already existed from a previous boot with different flags.
		if err := m.DB.Model(&ServiceConfig{}).
			Where("service = ? AND name = ? AND environment_id = ?", service, spec.Name, envID).
			Updates(map[string]any{
				"editable": spec.Editable,
				"info":     spec.Info,
			}).Error; err != nil {
			return fmt.Errorf("sync metadata %s/%s: %w", service, spec.Name, err)
		}
	}
	log.Debug().Msgf("Seeded service config for %s (%d sections)", service, len(SectionRegistry[service]))
	return nil
}

// GetSection retrieves one section by service and name.
func (m *ServiceConfigManager) GetSection(service, name string, envID uint) (ServiceConfig, error) {
	var sc ServiceConfig
	if err := m.DB.Where("service = ? AND name = ? AND environment_id = ?", service, name, envID).First(&sc).Error; err != nil {
		return ServiceConfig{}, err
	}
	return sc, nil
}

// GetAllByService retrieves all sections for a service.
func (m *ServiceConfigManager) GetAllByService(service string, envID uint) ([]ServiceConfig, error) {
	var values []ServiceConfig
	if err := m.DB.Where("service = ? AND environment_id = ?", service, envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// GetAll retrieves all sections across all services.
func (m *ServiceConfigManager) GetAll(envID uint) ([]ServiceConfig, error) {
	var values []ServiceConfig
	if err := m.DB.Where("environment_id = ?", envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// ErrSectionNotEditable is returned when UpdateSection is called on a section
// that is not marked editable in the registry.
var ErrSectionNotEditable = fmt.Errorf("section is not editable")

// UpdateSection replaces the JSON value of an editable section. It validates
// that the new value is valid JSON, that the section exists and is marked
// editable, and flips the source to SourceDB so subsequent boots won't
// clobber the change. Returns the updated row.
func (m *ServiceConfigManager) UpdateSection(service, name, value string, envID uint) (ServiceConfig, error) {
	if !m.VerifyService(service) {
		return ServiceConfig{}, fmt.Errorf("unknown service %q", service)
	}
	if !m.IsEditable(service, name) {
		return ServiceConfig{}, ErrSectionNotEditable
	}
	// Validate that the new value is valid JSON.
	if !json.Valid([]byte(value)) {
		return ServiceConfig{}, fmt.Errorf("value is not valid JSON")
	}
	existing, err := m.GetSection(service, name, envID)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("get section %s/%s: %w", service, name, err)
	}
	if err := m.DB.Model(&existing).Updates(map[string]any{
		"value":  value,
		"source": SourceDB,
	}).Error; err != nil {
		return ServiceConfig{}, fmt.Errorf("update %s/%s: %w", service, name, err)
	}
	log.Debug().Msgf("Updated service config %s/%s (source=db)", service, name)
	return existing, nil
}

// sectionValues extracts each registered section from ServiceParameters and
// marshals it to JSON. Returns a map of section-name → JSON-string.
func sectionValues(service string, cfg *config.ServiceParameters) (map[string]string, error) {
	out := make(map[string]string, len(SectionRegistry[service]))
	add := func(name string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		out[name] = string(raw)
		return nil
	}
	// Common sections present in both services.
	if cfg.Service != nil {
		if err := add("service", cfg.Service); err != nil {
			return nil, err
		}
	}
	if cfg.DB != nil {
		if err := add("db", cfg.DB); err != nil {
			return nil, err
		}
	}
	if cfg.Redis != nil {
		if err := add("redis", cfg.Redis); err != nil {
			return nil, err
		}
	}
	if cfg.Osquery != nil {
		if err := add("osquery", cfg.Osquery); err != nil {
			return nil, err
		}
	}
	if cfg.TLS != nil {
		if err := add("tls", cfg.TLS); err != nil {
			return nil, err
		}
	}
	if cfg.Logger != nil {
		if err := add("logger", cfg.Logger); err != nil {
			return nil, err
		}
	}
	if cfg.Carver != nil {
		if err := add("carver", cfg.Carver); err != nil {
			return nil, err
		}
	}
	if cfg.Debug != nil {
		if err := add("debug", cfg.Debug); err != nil {
			return nil, err
		}
	}
	// TLS-only sections.
	if service == config.ServiceTLS {
		if cfg.BatchWriter != nil {
			if err := add("batchWriter", cfg.BatchWriter); err != nil {
				return nil, err
			}
		}
		if cfg.ConfigEndpoints != nil {
			if err := add("configEndpoints", cfg.ConfigEndpoints); err != nil {
				return nil, err
			}
		}
		if cfg.Osctrld != nil {
			if err := add("osctrld", cfg.Osctrld); err != nil {
				return nil, err
			}
		}
		if cfg.Metrics != nil {
			if err := add("metrics", cfg.Metrics); err != nil {
				return nil, err
			}
		}
	}
	// API-only sections.
	if service == config.ServiceAPI {
		if cfg.SAML != nil {
			if err := add("saml", cfg.SAML); err != nil {
				return nil, err
			}
		}
		if cfg.OIDC != nil {
			if err := add("oidc", cfg.OIDC); err != nil {
				return nil, err
			}
		}
		if cfg.JWT != nil {
			if err := add("jwt", cfg.JWT); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// NoEnvironmentID is the sentinel environment ID for global (non-env-scoped)
// config rows. Mirrors settings.NoEnvironmentID.
const NoEnvironmentID = 0
