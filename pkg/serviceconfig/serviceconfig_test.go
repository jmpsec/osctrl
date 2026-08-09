package serviceconfig

import (
	"encoding/json"
	"testing"

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

	// Simulate an operator edit: change the logger section to source=db.
	sc, err := m.GetSection(config.ServiceTLS, "logger", 0)
	require.NoError(t, err)
	require.NoError(t, db.Model(&sc).Updates(map[string]any{
		"source": SourceDB,
		"value":  `{"type":"stdout","edited":true}`,
	}).Error)

	// Re-seed with a different logger config — the DB value must survive.
	cfg.Logger.Type = config.LoggingGraylog
	require.NoError(t, m.Seed(config.ServiceTLS, cfg, 0))

	sc2, err := m.GetSection(config.ServiceTLS, "logger", 0)
	require.NoError(t, err)
	assert.Equal(t, SourceDB, sc2.Source)
	assert.Equal(t, `{"type":"stdout","edited":true}`, sc2.Value)
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
	assert.NotContains(t, apiNames, "batchWriter")
	assert.NotContains(t, apiNames, "metrics")
	assert.NotContains(t, apiNames, "osctrld")

	assert.Contains(t, tlsNames, "batchWriter")
	assert.Contains(t, tlsNames, "configEndpoints")
	assert.Contains(t, tlsNames, "osctrld")
	assert.Contains(t, tlsNames, "metrics")
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

	assert.True(t, m.VerifySection(config.ServiceTLS, "logger"))
	assert.True(t, m.VerifySection(config.ServiceAPI, "saml"))
	assert.False(t, m.VerifySection(config.ServiceTLS, "saml"))
	assert.False(t, m.VerifySection(config.ServiceAPI, "metrics"))
	assert.False(t, m.VerifySection("bogus", "logger"))
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
	assert.False(t, m.IsEditable(config.ServiceTLS, "logger"))
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
