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
	// Overrides is a JSON array of the top-level fields an operator pinned in
	// this section. Only pinned fields beat flags, environment variables and
	// YAML at startup; every other field follows the process.
	//
	// Empty is meaningful and depends on Source:
	//   - source=yaml: nothing is pinned.
	//   - source=db:   a row written before pins existed (or replaced
	//     wholesale through the API), so EVERY field is pinned. That is the
	//     only reading that cannot silently drop an operator's edit, since the
	//     original YAML is gone once a row is overwritten.
	Overrides string `gorm:"type:text"`
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
		// Note: the "logger" section is no longer registered here. Log
		// sinks are now managed by pkg/logsinks (log_sinks table) with
		// its own API and frontend surface. Existing service_config
		// rows named "logger" from older boots are left in place and
		// ignored — they do not affect the running service.
		{"carver", false, "File carver configuration — may contain credentials"},
		{"debug", true, "HTTP debug dump settings"},
		{"rateLimits", true, "HTTP request rate limits"},
	},
	config.ServiceAPI: {
		{"service", true, "Core service listener, port, log level, auth mode"},
		{"db", false, "Backend connection — not DB-editable"},
		{"redis", false, "Redis connection — not DB-editable"},
		{"osquery", true, "osquery tables and feature toggles"},
		// "saml" and "oidc" are now managed by pkg/authproviders and
		// are intentionally absent from this registry. Existing
		// service_config rows named "saml"/"oidc" are left in place
		// and ignored.
		{"jwt", false, "JWT signing configuration — not DB-editable"},
		{"tls", false, "TLS termination certificate/key paths — not DB-editable"},
		// See the TLS registry: the "logger" section is now managed by
		// pkg/logsinks and is intentionally absent from this registry.
		{"carver", false, "File carver configuration — may contain credentials"},
		{"debug", true, "HTTP debug dump settings"},
		{"rateLimits", true, "HTTP request rate limits"},
	},
}

// NewServiceConfigManager initializes the manager and auto-migrates the
// service_config table.
func NewServiceConfigManager(backend *gorm.DB) *ServiceConfigManager {
	m := &ServiceConfigManager{DB: backend}
	if err := backend.AutoMigrate(&ServiceConfig{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (service_config): %v", err)
	}
	if err := backend.AutoMigrate(&ConfigFileStatus{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (config_file_statuses): %v", err)
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
		if err := m.refreshUnpinned(service, spec.Name, envID, raw); err != nil {
			return err
		}
	}
	log.Debug().Msgf("Seeded service config for %s (%d sections)", service, len(SectionRegistry[service]))
	return nil
}

// refreshUnpinned keeps every field of an existing row that the operator has
// NOT pinned equal to the configuration this process started with, so the
// stored value (which the UI renders as the current setting) matches what is
// actually running.
//
// Without this, per-field overrides would make the display lie: a flag changed
// since the first boot would run, while the page showed the value seeded
// months ago. Pinned fields are never touched, and a row whose every field is
// pinned (a legacy or wholesale-replaced row) is left byte-for-byte alone.
func (m *ServiceConfigManager) refreshUnpinned(service, name string, envID uint, fresh string) error {
	sc, err := m.GetSection(service, name, envID)
	if err != nil {
		return fmt.Errorf("read %s/%s for refresh: %w", service, name, err)
	}
	pins := sc.pinSet()
	if pins.all {
		return nil
	}
	merged, changed := mergeUnpinned(sc.Value, fresh, pins)
	if !changed {
		return nil
	}
	if err := m.DB.Model(&sc).Update("value", merged).Error; err != nil {
		return fmt.Errorf("refresh %s/%s: %w", service, name, err)
	}
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

// Resolve applies DB-edited sections back into ServiceParameters so the
// service uses the operator's DB values at runtime instead of the YAML
// defaults. For each section with source=db, the JSON value is unmarshaled
// into the matching ServiceParameters field, overriding the YAML value.
// Sections with source=yaml are skipped — the YAML value is already in
// ServiceParameters from the initial load.
//
// This is the core of phase 3: the YAML file bootstraps the config, the DB
// overrides it for sections the operator has edited through the API.
//
// PRECEDENCE: a source=db row beats command-line flags and environment
// variables, not just YAML. That is what makes "Apply & Restart" take effect,
// but it surprises anyone who passes --port and watches the service ignore
// it — and because the API stores a whole section per save, one edited field
// pins every other field in that section too. So every field a row actually
// changes is logged at Info; a row that matches what the process already had
// is not worth a line.
func (m *ServiceConfigManager) Resolve(service string, cfg *config.ServiceParameters, envID uint) error {
	if !m.VerifyService(service) {
		return fmt.Errorf("unknown service %q", service)
	}
	if cfg == nil {
		return fmt.Errorf("nil ServiceParameters for %s", service)
	}
	sections, err := m.GetAllByService(service, envID)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", service, err)
	}
	// Sections are independent fields of ServiceParameters, so one snapshot
	// taken before any row is applied is a valid "before" for every section.
	before, err := sectionValues(service, cfg)
	if err != nil {
		return fmt.Errorf("resolve %s: snapshot before overrides: %w", service, err)
	}
	var applied []string
	for _, sc := range sections {
		// Only DB-edited rows override the YAML defaults.
		if sc.Source != SourceDB {
			continue
		}
		// Only the fields the operator pinned beat flags, environment and
		// YAML. A row from before pins existed pins every field.
		ok, err := applySection(cfg, sc.Name, filterToPins(sc.Value, sc.pinSet()))
		if err != nil {
			return fmt.Errorf("resolve %s/%s: %w", service, sc.Name, err)
		}
		if ok {
			log.Debug().Msgf("Resolved service config %s/%s from DB (source=db)", service, sc.Name)
			applied = append(applied, sc.Name)
		} else {
			log.Debug().Msgf("Skipped service config %s/%s — section is nil in ServiceParameters", service, sc.Name)
		}
	}
	if len(applied) == 0 {
		return nil
	}
	after, err := sectionValues(service, cfg)
	if err != nil {
		// Reporting is best effort: the overrides are already applied, and a
		// marshal failure here must not stop the service from booting.
		log.Warn().Err(err).Msgf("service config %s: could not describe database overrides", service)
		return nil
	}
	for _, sc := range sections {
		if sc.Source != SourceDB {
			continue
		}
		for _, name := range applied {
			if name == sc.Name {
				m.logOverride(service, sc, before[name], after[name])
			}
		}
	}
	return nil
}

// logOverride reports what one database row changed. A row identical to what
// the process already had logs nothing at Info.
func (m *ServiceConfigManager) logOverride(service string, sc ServiceConfig, before, after string) {
	changes, whole := diffSections(before, after)
	section := sc.Name
	switch {
	case whole:
		log.Info().Str("service", service).Str("section", section).
			Msg("service config: database row replaces this section, overriding flags, environment and YAML")
	case len(changes) > 0:
		msg := "service config: pinned fields in the database override flags, environment and YAML"
		if sc.pinSet().all {
			// Say why untouched-looking fields moved too: this row predates
			// per-field pins, or was replaced as a whole.
			msg = "service config: this database row pins EVERY field in the section (it predates per-field " +
				"overrides, or was replaced as a whole), so it overrides flags, environment and YAML; " +
				"release fields with a reset to follow the process again"
		}
		log.Info().Str("service", service).Str("section", section).
			Str("fields", describeChanges(changes, m.IsEditable(service, section))).
			Msg(msg)
	}
}

// applySection unmarshals a JSON section value into the matching field on
// ServiceParameters. If the target field is nil (section absent from the
// YAML), the value is skipped and applied=false is returned. Unknown sections
// are also skipped.
func applySection(cfg *config.ServiceParameters, name, value string) (bool, error) {
	switch name {
	case "service":
		if cfg.Service != nil {
			return true, json.Unmarshal([]byte(value), cfg.Service)
		}
	case "db":
		if cfg.DB != nil {
			return true, json.Unmarshal([]byte(value), cfg.DB)
		}
	case "redis":
		if cfg.Redis != nil {
			return true, json.Unmarshal([]byte(value), cfg.Redis)
		}
	case "osquery":
		if cfg.Osquery != nil {
			return true, json.Unmarshal([]byte(value), cfg.Osquery)
		}
	case "tls":
		if cfg.TLS != nil {
			return true, json.Unmarshal([]byte(value), cfg.TLS)
		}
	case "logger":
		if cfg.Logger != nil {
			return true, json.Unmarshal([]byte(value), cfg.Logger)
		}
	case "carver":
		if cfg.Carver != nil {
			return true, json.Unmarshal([]byte(value), cfg.Carver)
		}
	case "debug":
		if cfg.Debug != nil {
			return true, json.Unmarshal([]byte(value), cfg.Debug)
		}
	case "rateLimits":
		if cfg.RateLimits != nil {
			return true, json.Unmarshal([]byte(value), cfg.RateLimits)
		}
	case "batchWriter":
		if cfg.BatchWriter != nil {
			return true, json.Unmarshal([]byte(value), cfg.BatchWriter)
		}
	case "configEndpoints":
		if cfg.ConfigEndpoints != nil {
			return true, json.Unmarshal([]byte(value), cfg.ConfigEndpoints)
		}
	case "osctrld":
		if cfg.Osctrld != nil {
			return true, json.Unmarshal([]byte(value), cfg.Osctrld)
		}
	case "metrics":
		if cfg.Metrics != nil {
			return true, json.Unmarshal([]byte(value), cfg.Metrics)
		}
	case "saml":
		if cfg.SAML != nil {
			return true, json.Unmarshal([]byte(value), cfg.SAML)
		}
	case "oidc":
		if cfg.OIDC != nil {
			return true, json.Unmarshal([]byte(value), cfg.OIDC)
		}
	case "jwt":
		if cfg.JWT != nil {
			return true, json.Unmarshal([]byte(value), cfg.JWT)
		}
	}
	return false, nil
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
	if err := validateSectionValue(service, name, value); err != nil {
		return ServiceConfig{}, err
	}
	existing, err := m.GetSection(service, name, envID)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("get section %s/%s: %w", service, name, err)
	}
	// Replacing a section wholesale cannot say which fields the caller meant
	// to pin, so it pins them all: the same behavior every row had before pins
	// existed. Callers that know what they changed use PatchSection instead.
	if err := m.DB.Model(&existing).Updates(map[string]any{
		"value":     value,
		"source":    SourceDB,
		"overrides": "",
	}).Error; err != nil {
		return ServiceConfig{}, fmt.Errorf("update %s/%s: %w", service, name, err)
	}
	log.Debug().Msgf("Updated service config %s/%s (source=db)", service, name)
	return existing, nil
}

// validateSectionValue checks a candidate section value. It is shared by the
// whole-section and field-level paths so the two can never accept different
// things.
func validateSectionValue(service, name, value string) error {
	if !json.Valid([]byte(value)) {
		return fmt.Errorf("value is not valid JSON")
	}
	if name == "osquery" {
		var osquery config.YAMLConfigurationOsquery
		if err := json.Unmarshal([]byte(value), &osquery); err != nil {
			return fmt.Errorf("unmarshal osquery: %w", err)
		}
	}
	if name == "rateLimits" {
		var limits config.YAMLConfigurationRateLimits
		if err := json.Unmarshal([]byte(value), &limits); err != nil {
			return fmt.Errorf("unmarshal rateLimits: %w", err)
		}
		names := []string{"enroll"}
		if service == config.ServiceAPI {
			names = []string{"login", "preAuth", "serviceConfigApply"}
		}
		if err := config.ValidateRateLimits(limits, names...); err != nil {
			return err
		}
	}
	return nil
}

// PatchSection changes individual top-level fields of an editable section.
//
//   - set pins each named field to the given value. Only pinned fields beat
//     flags, environment variables and YAML at startup.
//   - reset releases each named field, so it follows the process again from the
//     next restart (the stored value is refreshed by Seed then).
//
// This is the field-level counterpart of UpdateSection, which replaces a whole
// section and therefore pins every field in it. When the last pin is released
// the row returns to source=yaml.
//
// Field names are matched case-insensitively, the way encoding/json matches
// them, and stored under the spelling the section already uses. A name the
// section does not have is an error rather than a no-op.
func (m *ServiceConfigManager) PatchSection(service, name string, set map[string]json.RawMessage, reset []string, envID uint) (ServiceConfig, error) {
	if !m.VerifyService(service) {
		return ServiceConfig{}, fmt.Errorf("unknown service %q", service)
	}
	if !m.IsEditable(service, name) {
		return ServiceConfig{}, ErrSectionNotEditable
	}
	if len(set) == 0 && len(reset) == 0 {
		return ServiceConfig{}, ErrEmptyPatch
	}
	existing, err := m.GetSection(service, name, envID)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("get section %s/%s: %w", service, name, err)
	}
	fields, err := orderedFields(existing.Value)
	if err != nil {
		return ServiceConfig{}, ErrSectionNotPatchable
	}
	canon := canonicalKeys(fields)

	// Resolve every name to the section's own spelling, rejecting strangers
	// and a field named twice.
	setCanon := make(map[string]json.RawMessage, len(set))
	for key, raw := range set {
		c, ok := canon[norm(key)]
		if !ok {
			return ServiceConfig{}, fmt.Errorf("%w: %q", ErrUnknownField, key)
		}
		if _, dup := setCanon[c]; dup {
			return ServiceConfig{}, fmt.Errorf("field %q given more than once", c)
		}
		setCanon[c] = compact(raw)
	}
	resetCanon := make(map[string]bool, len(reset))
	for _, key := range reset {
		c, ok := canon[norm(key)]
		if !ok {
			return ServiceConfig{}, fmt.Errorf("%w: %q", ErrUnknownField, key)
		}
		if _, both := setCanon[c]; both {
			return ServiceConfig{}, fmt.Errorf("field %q cannot be both set and reset", c)
		}
		resetCanon[c] = true
	}

	// New value: the existing fields, in order, with the patched ones replaced.
	for i, f := range fields {
		if raw, ok := setCanon[f.Key]; ok {
			fields[i].Raw = raw
		}
	}
	newValue, err := renderFields(fields)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("render %s/%s: %w", service, name, err)
	}
	if err := validateSectionValue(service, name, newValue); err != nil {
		return ServiceConfig{}, err
	}

	// New pins: what was pinned, plus what is set, minus what is reset. A row
	// that pinned everything (legacy) is expanded to the explicit list first,
	// which is what lets a single field be released from it.
	current := existing.pinSet()
	pinned := make(map[string]bool, len(fields))
	for _, f := range fields {
		if current.has(f.Key) {
			pinned[f.Key] = true
		}
	}
	for c := range setCanon {
		pinned[c] = true
	}
	for c := range resetCanon {
		delete(pinned, c)
	}

	updates := map[string]any{"value": newValue}
	if len(pinned) == 0 {
		updates["source"] = SourceYAML
		updates["overrides"] = ""
	} else {
		keys := make([]string, 0, len(pinned))
		for k := range pinned {
			keys = append(keys, k)
		}
		updates["source"] = SourceDB
		updates["overrides"] = encodePins(keys)
	}
	if err := m.DB.Model(&existing).Updates(updates).Error; err != nil {
		return ServiceConfig{}, fmt.Errorf("patch %s/%s: %w", service, name, err)
	}
	log.Debug().Msgf("Patched service config %s/%s (%d set, %d reset, %d pinned)", service, name, len(setCanon), len(resetCanon), len(pinned))
	return m.GetSection(service, name, envID)
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
	if cfg.RateLimits != nil {
		if err := add("rateLimits", cfg.RateLimits); err != nil {
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
