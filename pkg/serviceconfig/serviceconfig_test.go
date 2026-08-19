package serviceconfig

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")
	require.NoError(t, db.AutoMigrate(&ServiceConfig{}), "Failed to migrate schema")
	return db
}

func testTLSParams() *config.ServiceParameters {
	return &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{
			Listener: "0.0.0.0",
			Port:     9000,
			Host:     "tls.example.com",
			Auth:     config.AuthNone,
		},
		DB: &config.YAMLConfigurationDB{
			Type: config.DBTypeSQLite,
			Name: "osctrl",
		},
		Redis: &config.YAMLConfigurationRedis{
			Host: "127.0.0.1",
			Port: 6379,
		},
		Osquery: &config.YAMLConfigurationOsquery{
			Version:    "5.12.1",
			TablesFile: "./data/5.12.1.json",
		},
		ConfigEndpoints: &config.YAMLConfigurationEndpoints{
			{Environment: "prod", Secret: "s3cr3t"},
		},
		Osctrld: &config.YAMLConfigurationOsctrld{Enabled: false},
		Metrics: &config.YAMLConfigurationMetrics{Enabled: true, Port: 9090},
		TLS:     &config.YAMLConfigurationTLS{Termination: true, CertificateFile: "/certs/tls.crt"},
		Logger:  &config.YAMLConfigurationLogger{Type: config.LoggingDB, LoggerDBSame: true},
		Carver:  &config.YAMLConfigurationCarver{Type: config.CarverLocal, Local: &config.LocalCarver{CarvesDir: "/carves"}},
		Debug:   &config.YAMLConfigurationDebug{EnableHTTP: false},
		RateLimits: &config.YAMLConfigurationRateLimits{
			Enroll: config.YAMLConfigurationRateLimit{Burst: 20, Period: time.Minute, EvictAfter: 10 * time.Minute, RetryAfter: 60},
		},
		BatchWriter: &config.YAMLConfigurationWriter{
			WriterBatchSize:  50,
			WriterBufferSize: 2000,
		},
	}
}

func testAPIParams() *config.ServiceParameters {
	return &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{
			Listener: "0.0.0.0",
			Port:     8000,
			Host:     "api.example.com",
			Auth:     config.AuthJWT,
		},
		DB: &config.YAMLConfigurationDB{
			Type: config.DBTypePostgres,
			Host: "db.internal",
		},
		Redis: &config.YAMLConfigurationRedis{Host: "127.0.0.1"},
		Osquery: &config.YAMLConfigurationOsquery{
			Version:    "5.12.1",
			TablesFile: "./data/5.12.1.json",
		},
		SAML: &config.YAMLConfigurationSAML{Enabled: true, EntityID: "https://api/saml"},
		OIDC: &config.YAMLConfigurationOIDC{Enabled: false, IssuerURL: "https://idp"},
		JWT:  &config.YAMLConfigurationJWT{JWTSecret: "secret", HoursToExpire: 3},
		TLS:  &config.YAMLConfigurationTLS{Termination: true},
		Logger: &config.YAMLConfigurationLogger{
			Type: config.LoggingStdout,
			DB:   &config.YAMLConfigurationDB{},
		},
		Carver: &config.YAMLConfigurationCarver{Type: config.CarverDB},
		Debug:  &config.YAMLConfigurationDebug{EnableHTTP: false},
		RateLimits: &config.YAMLConfigurationRateLimits{
			Login:              config.YAMLConfigurationRateLimit{Burst: 10, Period: time.Minute, EvictAfter: 10 * time.Minute, RetryAfter: 60},
			PreAuth:            config.YAMLConfigurationRateLimit{Burst: 60, Period: time.Minute, EvictAfter: 10 * time.Minute, RetryAfter: 60},
			ServiceConfigApply: config.YAMLConfigurationRateLimit{Burst: 3, Period: 10 * time.Minute, EvictAfter: 30 * time.Minute, RetryAfter: 60},
		},
	}
}

// Seed must create a row for every registered section when none exist.
func TestSeed_CreatesAllSections(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	rows, err := m.GetAllByService(config.ServiceTLS, 0)
	require.NoError(t, err)
	assert.Len(t, rows, len(SectionRegistry[config.ServiceTLS]))

	// Every registered section name should be present.
	names := make(map[string]bool, len(rows))
	editableByRow := make(map[string]bool, len(rows))
	for _, r := range rows {
		names[r.Name] = true
		editableByRow[r.Name] = r.Editable
		assert.Equal(t, SourceYAML, r.Source)
		assert.Equal(t, "json", r.Type)
	}
	for _, spec := range SectionRegistry[config.ServiceTLS] {
		assert.True(t, names[spec.Name], "missing section %s", spec.Name)
		assert.Equal(t, spec.Editable, editableByRow[spec.Name],
			"editable flag mismatch for %s", spec.Name)
	}
}

// Seed must be idempotent: running it twice must not duplicate or overwrite
// rows.
func TestSeed_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	rows, err := m.GetAllByService(config.ServiceTLS, 0)
	require.NoError(t, err)
	assert.Len(t, rows, len(SectionRegistry[config.ServiceTLS]))
}

// Seed must not overwrite a row that was already edited via the DB (source=db).
// This is the key safety property: once an operator edits a section, subsequent
// boots must not clobber it.
func TestSeed_DoesNotOverwriteDBEditedRow(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Simulate an operator edit: change the osquery section to source=db.
	// (The "logger" section is no longer registered — it is managed by
	// pkg/logsinks — so we use osquery, which is seeded and editable.)
	sc, err := m.GetSection(config.ServiceTLS, "osquery", 0)
	require.NoError(t, err)
	require.NoError(t, db.Model(&sc).Updates(map[string]any{
		"source": SourceDB,
		"value":  `{"version":"9.9.9","tablesFile":"./x.json","logger":true,"config":true,"query":true,"carve":true,"accelerated":false,"console":false,"fileExplorer":false,"readOnly":false}`,
	}).Error)

	// Re-seed with a different osquery config — the DB value must survive.
	cfg.Osquery.Version = "5.12.2"
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc2, err := m.GetSection(config.ServiceTLS, "osquery", 0)
	require.NoError(t, err)
	assert.Equal(t, SourceDB, sc2.Source)
	assert.Contains(t, sc2.Value, "9.9.9")
}

// The seeded JSON must round-trip back to the original struct.
func TestSeed_JSONRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc, err := m.GetSection(config.ServiceTLS, "service", 0)
	require.NoError(t, err)

	var got config.YAMLConfigurationService
	require.NoError(t, json.Unmarshal([]byte(sc.Value), &got))
	assert.Equal(t, cfg.Service.Listener, got.Listener)
	assert.Equal(t, cfg.Service.Port, got.Port)
	assert.Equal(t, cfg.Service.Host, got.Host)
	assert.Equal(t, cfg.Service.Auth, got.Auth)
}

// API sections (saml, oidc, jwt) must be seeded for the API service but absent
// for TLS, and vice-versa for batchWriter/configEndpoints/osctrld/metrics.
func TestSeed_ServiceSpecificSections(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}

	require.NoError(t, m.Seed(config.ServiceAPI, testAPIParams(), 0))
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))

	apiRows, err := m.GetAllByService(config.ServiceAPI, 0)
	require.NoError(t, err)
	tlsRows, err := m.GetAllByService(config.ServiceTLS, 0)
	require.NoError(t, err)

	apiNames := sectionNames(apiRows)
	tlsNames := sectionNames(tlsRows)

	assert.Contains(t, apiNames, "saml")
	assert.Contains(t, apiNames, "oidc")
	assert.Contains(t, apiNames, "jwt")
	assert.Contains(t, apiNames, "rateLimits")
	assert.NotContains(t, apiNames, "batchWriter")
	assert.NotContains(t, apiNames, "metrics")
	assert.NotContains(t, apiNames, "osctrld")

	assert.Contains(t, tlsNames, "batchWriter")
	assert.Contains(t, tlsNames, "configEndpoints")
	assert.Contains(t, tlsNames, "osctrld")
	assert.Contains(t, tlsNames, "metrics")
	assert.Contains(t, tlsNames, "rateLimits")
	assert.NotContains(t, tlsNames, "saml")
	assert.NotContains(t, tlsNames, "oidc")
	assert.NotContains(t, tlsNames, "jwt")
}

// Seed must reject an unknown service.
func TestSeed_UnknownService(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	err := m.Seed("bogus", testTLSParams(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

// Seed must reject a nil config.
func TestSeed_NilConfig(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	err := m.Seed(config.ServiceTLS, nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil ServiceParameters")
}

// GetSection must return ErrRecordNotFound for a missing section.
func TestGetSection_NotFound(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	_, err := m.GetSection(config.ServiceTLS, "nonexistent", 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

// GetAll must return sections for both services.
func TestGetAll(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}

	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))
	require.NoError(t, m.Seed(config.ServiceAPI, testAPIParams(), 0))

	all, err := m.GetAll(0)
	require.NoError(t, err)
	expected := len(SectionRegistry[config.ServiceTLS]) + len(SectionRegistry[config.ServiceAPI])
	assert.Len(t, all, expected)
}

// VerifyService and VerifySection must correctly validate inputs.
func TestVerifyServiceAndSection(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}

	assert.True(t, m.VerifyService(config.ServiceTLS))
	assert.True(t, m.VerifyService(config.ServiceAPI))
	assert.False(t, m.VerifyService("bogus"))

	// "logger" is no longer registered (managed by pkg/logsinks); use
	// "osquery" and "metrics" as the representative registered sections.
	assert.True(t, m.VerifySection(config.ServiceTLS, "osquery"))
	assert.True(t, m.VerifySection(config.ServiceAPI, "saml"))
	assert.False(t, m.VerifySection(config.ServiceTLS, "saml"))
	assert.False(t, m.VerifySection(config.ServiceAPI, "metrics"))
	assert.False(t, m.VerifySection("bogus", "osquery"))
}

// Seeding with different environment IDs must produce independent rows.
func TestSeed_PerEnvironmentIsolation(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 5))

	rows0, err := m.GetAllByService(config.ServiceTLS, 0)
	require.NoError(t, err)
	rows5, err := m.GetAllByService(config.ServiceTLS, 5)
	require.NoError(t, err)

	assert.Len(t, rows0, len(SectionRegistry[config.ServiceTLS]))
	assert.Len(t, rows5, len(SectionRegistry[config.ServiceTLS]))
	for _, r := range rows0 {
		assert.Equal(t, uint(0), r.EnvironmentID)
	}
	for _, r := range rows5 {
		assert.Equal(t, uint(5), r.EnvironmentID)
	}
}

func sectionNames(rows []ServiceConfig) map[string]bool {
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Name] = true
	}
	return out
}

// Seed must sync the Editable flag from the registry to existing rows.
// This is the regression for the bug where rows seeded before a section was
// marked editable kept the stale Editable=false, so the frontend never
// showed the Edit button even though the registry said it was editable.
func TestSeed_SyncsEditableFlagToExistingRows(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	// Seed with all sections non-editable by temporarily swapping the
	// registry. We can't easily swap the global, so instead we manually
	// insert rows with Editable=false and then re-seed — the sync should
	// flip the debug row's Editable to true.
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Force the debug row's Editable to false (simulating a stale row
	// from before debug was marked editable).
	require.NoError(t, db.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceTLS, "debug").
		Update("editable", false).Error)

	// Re-seed — the sync must flip Editable back to true.
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc, err := m.GetSection(config.ServiceTLS, "debug", 0)
	require.NoError(t, err)
	assert.True(t, sc.Editable, "Seed must sync Editable=true for debug section to existing rows")
}

// Seed must sync the Info text from the registry to existing rows.
func TestSeed_SyncsInfoToExistingRows(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Corrupt the info on the service row.
	require.NoError(t, db.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceTLS, "service").
		Update("info", "stale info").Error)

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc, err := m.GetSection(config.ServiceTLS, "service", 0)
	require.NoError(t, err)
	assert.Equal(t, "Core service listener, port, log level, auth mode", sc.Info)
}

// UpdateSection must update the value and flip source to "db" for an editable
// section.
func TestUpdateSection_Success(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))

	newValue := `{"enableHttp":true,"httpFile":"/tmp/debug.log","showBody":true}`
	updated, err := m.UpdateSection(config.ServiceTLS, "debug", newValue, 0)
	require.NoError(t, err)
	assert.Equal(t, newValue, updated.Value)
	assert.Equal(t, SourceDB, updated.Source)
}

// UpdateSection must reject a non-editable section with ErrSectionNotEditable.
func TestUpdateSection_NotEditable(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))

	_, err := m.UpdateSection(config.ServiceTLS, "db", `{"host":"x"}`, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSectionNotEditable)
}

// UpdateSection must reject invalid JSON.
func TestUpdateSection_InvalidJSON(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))

	_, err := m.UpdateSection(config.ServiceTLS, "debug", "not-json", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

// UpdateSection must reject an unknown service.
func TestUpdateSection_UnknownService(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	_, err := m.UpdateSection("bogus", "debug", `{}`, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

// UpdateSection must reject a section that doesn't exist in the DB.
func TestUpdateSection_SectionNotFound(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	// "debug" is editable but we haven't seeded — should fail on GetSection.
	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{}`, 0)
	require.Error(t, err)
}

// IsEditable must return true for editable sections and false for
// non-editable or unknown sections.
func TestIsEditable(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}

	assert.True(t, m.IsEditable(config.ServiceTLS, "debug"))
	assert.True(t, m.IsEditable(config.ServiceAPI, "debug"))
	assert.False(t, m.IsEditable(config.ServiceTLS, "db"))
	// "logger" is no longer registered; verify it reports not-editable
	// (it is not a known section at all now).
	assert.False(t, m.IsEditable(config.ServiceTLS, "logger"))
	assert.True(t, m.IsEditable(config.ServiceTLS, "rateLimits"))
	assert.True(t, m.IsEditable(config.ServiceAPI, "rateLimits"))
	assert.False(t, m.IsEditable(config.ServiceTLS, "nonexistent"))
	assert.False(t, m.IsEditable("bogus", "debug"))
}

// After UpdateSection flips source to "db", a subsequent Seed must not
// overwrite the edited value.
func TestUpdateSection_SeedDoesNotClobber(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	newValue := `{"enableHttp":true,"httpFile":"/tmp/x.log","showBody":false}`
	_, err := m.UpdateSection(config.ServiceTLS, "debug", newValue, 0)
	require.NoError(t, err)

	// Re-seed — debug is create-if-missing so the DB value survives.
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc, err := m.GetSection(config.ServiceTLS, "debug", 0)
	require.NoError(t, err)
	assert.Equal(t, newValue, sc.Value)
	assert.Equal(t, SourceDB, sc.Source)
}

// ──────────────────────────────────────────────────────────────────────────────
// Resolve — phase 3 DB-first consumption
// ──────────────────────────────────────────────────────────────────────────────

// Resolve must be a no-op when no sections have source=db — the YAML
// values in ServiceParameters must be unchanged.
func TestResolve_NoDBEdits_KeepsYAMLValues(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	originalPort := cfg.Service.Port
	originalListener := cfg.Service.Listener

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))

	assert.Equal(t, originalPort, cfg.Service.Port)
	assert.Equal(t, originalListener, cfg.Service.Listener)
}

// Resolve must override ServiceParameters fields when a section has
// source=db.
func TestResolve_DBEditedSection_OverridesYAML(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Edit the debug section via the API (flips source to db).
	newDebug := `{"enableHttp":true,"httpFile":"/tmp/debug.log","showBody":true}`
	_, err := m.UpdateSection(config.ServiceTLS, "debug", newDebug, 0)
	require.NoError(t, err)

	// Resolve must apply the DB value to cfg.Debug.
	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))
	assert.True(t, cfg.Debug.EnableHTTP)
	assert.Equal(t, "/tmp/debug.log", cfg.Debug.HTTPFile)
	assert.True(t, cfg.Debug.ShowBody)
}

// Resolve must override the service section (listener, port, host) when it
// has been edited via the DB.
func TestResolve_ServiceSection_OverridesYAML(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Edit the service section via the API.
	newService := `{"listener":"127.0.0.1","port":9999,"host":"db.example.com","logLevel":"debug","logFormat":"json","auth":"none","auditLog":true,"postureEnabled":false,"postureQueryPrefix":"","trustedProxies":"","dbHealthCheck":false,"dbHealthInterval":0,"dbHealthThreshold":0,"geoipDBPath":""}`
	_, err := m.UpdateSection(config.ServiceTLS, "service", newService, 0)
	require.NoError(t, err)

	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))
	assert.Equal(t, "127.0.0.1", cfg.Service.Listener)
	assert.Equal(t, 9999, cfg.Service.Port)
	assert.Equal(t, "db.example.com", cfg.Service.Host)
	assert.Equal(t, "debug", cfg.Service.LogLevel)
	assert.True(t, cfg.Service.AuditLog)
}

// Resolve must not override YAML values for sections with source=yaml.
func TestResolve_YAMLSourceSectionsAreSkipped(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	originalDBHost := cfg.DB.Host

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	// db section is source=yaml (not editable, never edited).
	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))

	// DB host must still be the YAML value.
	assert.Equal(t, originalDBHost, cfg.DB.Host)
}

// Resolve must reject an unknown service.
func TestResolve_UnknownService(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	err := m.Resolve("bogus", testTLSParams(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

// Resolve must reject a nil config.
func TestResolve_NilConfig(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	err := m.Resolve(config.ServiceTLS, nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil ServiceParameters")
}

// Resolve + Seed + Update + Resolve round-trip: edit a section via the API,
// re-seed (which doesn't clobber), resolve, and verify the DB value wins
// over the YAML value.
func TestResolve_FullRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()

	// Boot 1: seed from YAML, no DB edits, resolve is a no-op.
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))
	assert.False(t, cfg.Debug.EnableHTTP) // YAML default

	// Operator edits debug via the API.
	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"httpFile":"/tmp/x.log","showBody":false}`, 0)
	require.NoError(t, err)

	// Boot 2: re-seed (doesn't clobber DB edit), then resolve.
	cfg2 := testTLSParams() // fresh YAML load
	require.NoError(t, m.Seed(config.ServiceTLS, cfg2, 0))
	require.NoError(t, m.Resolve(config.ServiceTLS, cfg2, 0))

	// The DB value must win over the YAML default.
	assert.True(t, cfg2.Debug.EnableHTTP)
	assert.Equal(t, "/tmp/x.log", cfg2.Debug.HTTPFile)
	assert.False(t, cfg2.Debug.ShowBody)
}

// Resolve must handle multiple DB-edited sections simultaneously.
func TestResolve_MultipleDBEdits(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Edit multiple sections.
	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"httpFile":"/tmp/a.log","showBody":false,"hostIdentifier":""}`, 0)
	require.NoError(t, err)
	_, err = m.UpdateSection(config.ServiceTLS, "osquery", `{"version":"5.12.2","tablesFile":"./data/5.12.2.json","logger":true,"config":true,"query":true,"carve":true,"accelerated":false,"fileExplorer":false,"readOnly":false}`, 0)
	require.NoError(t, err)

	require.NoError(t, m.Resolve(config.ServiceTLS, cfg, 0))
	assert.True(t, cfg.Debug.EnableHTTP)
	assert.Equal(t, "5.12.2", cfg.Osquery.Version)
	assert.Equal(t, "./data/5.12.2.json", cfg.Osquery.TablesFile)
}

func TestResolve_RateLimitsSection_OverridesYAML(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := testAPIParams()
	require.NoError(t, m.Seed(config.ServiceAPI, cfg, 0))

	_, err := m.UpdateSection(config.ServiceAPI, "rateLimits", `{"login":{"burst":7,"period":60000000000,"evictAfter":600000000000,"retryAfter":23},"preAuth":{"burst":60,"period":60000000000,"evictAfter":600000000000,"retryAfter":60},"serviceConfigApply":{"burst":3,"period":600000000000,"evictAfter":1800000000000,"retryAfter":60},"enroll":{"burst":20,"period":60000000000,"evictAfter":600000000000,"retryAfter":60}}`, 0)
	require.NoError(t, err)

	require.NoError(t, m.Resolve(config.ServiceAPI, cfg, 0))
	assert.Equal(t, 7, cfg.RateLimits.Login.Burst)
	assert.Equal(t, 23, cfg.RateLimits.Login.RetryAfter)
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 4 — optional YAML (nil section pointers)
// ──────────────────────────────────────────────────────────────────────────────

// minimalTLSParams returns a ServiceParameters with only the required
// sections (service, db, redis) — all optional sections are nil, simulating
// a minimal YAML file that only specifies connection info.
func minimalTLSParams() *config.ServiceParameters {
	return &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{
			Listener: "0.0.0.0",
			Port:     9000,
			Host:     "tls.example.com",
			Auth:     config.AuthNone,
		},
		DB: &config.YAMLConfigurationDB{
			Type: config.DBTypeSQLite,
			Name: "osctrl",
		},
		Redis: &config.YAMLConfigurationRedis{
			Host: "127.0.0.1",
			Port: 6379,
		},
		// All optional sections are nil — simulating a minimal YAML.
	}
}

// Seed must not panic when optional section pointers are nil. It should
// only seed the sections that are present.
func TestSeed_NilOptionalSections_DoesNotPanic(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}
	cfg := minimalTLSParams()

	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	// Only service, db, redis should be present — the rest are nil.
	rows, err := m.GetAllByService(config.ServiceTLS, 0)
	require.NoError(t, err)
	// 3 required sections + 0 optional = 3 rows.
	assert.Len(t, rows, 3)
	names := sectionNames(rows)
	assert.True(t, names["service"])
	assert.True(t, names["db"])
	assert.True(t, names["redis"])
	assert.False(t, names["debug"])
	assert.False(t, names["osquery"])
}

// Resolve must not panic when optional section pointers are nil, even if a
// DB row with source=db exists for a nil section. The nil section is simply
// skipped — the operator can't have edited it through the API (it was never
// seeded), so this only happens if someone manually inserted a DB row.
func TestResolve_NilOptionalSection_DBValueIgnored(t *testing.T) {
	db := setupTestDB(t)
	m := &ServiceConfigManager{DB: db}

	// First boot with full config to seed all sections.
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))

	// Edit debug via the API.
	_, err := m.UpdateSection(config.ServiceTLS, "debug", `{"enableHttp":true,"httpFile":"/tmp/x.log","showBody":false,"hostIdentifier":""}`, 0)
	require.NoError(t, err)

	// Second boot with minimal YAML — debug is nil in ServiceParameters.
	cfg := minimalTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))
	// Resolve must not panic even though debug has source=db in the DB
	// but cfg.Debug is nil.
	require.NotPanics(t, func() {
		_ = m.Resolve(config.ServiceTLS, cfg, 0)
	})

	// cfg.Debug is still nil — Resolve skipped it because the pointer was nil.
	assert.Nil(t, cfg.Debug)
}
