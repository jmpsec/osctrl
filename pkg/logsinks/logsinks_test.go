package logsinks

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *LogSinksManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&LogSink{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return &LogSinksManager{DB: db}
}

func TestRegistryCoversAllYAMLTypes(t *testing.T) {
	want := []string{
		config.LoggingNone, config.LoggingStdout, config.LoggingFile,
		config.LoggingDB, config.LoggingGraylog, config.LoggingSplunk,
		config.LoggingLogstash, config.LoggingKinesis, config.LoggingS3,
		config.LoggingKafka, config.LoggingElastic,
	}
	for _, w := range want {
		if _, ok := Registry[w]; !ok {
			t.Errorf("Registry missing type %q", w)
		}
	}
	if len(Registry) != len(want) {
		t.Errorf("Registry has %d entries, expected %d (no extra types)", len(Registry), len(want))
	}
}

func TestSupportedTypesIsSortedAndComplete(t *testing.T) {
	got := SupportedTypes()
	if len(got) != len(Registry) {
		t.Fatalf("SupportedTypes returned %d, want %d", len(got), len(Registry))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("SupportedTypes not sorted: %v", got)
		}
	}
}

func TestValidateTypeIsStrictCase(t *testing.T) {
	// ValidateType is intentionally strict (Registry keys are
	// lower-case). Create/Update normalize input before calling it.
	if ValidateType("Splunk") {
		t.Error("ValidateType should not accept mixed case")
	}
	if !ValidateType(config.LoggingSplunk) {
		t.Error("ValidateType should accept the canonical lower-case key")
	}
}

func TestCreateNormalizesTypeCase(t *testing.T) {
	m := newTestManager(t)
	row, err := m.Create("ci", "SPLUNK", true, 0, `{"url":"","token":"","host":"","index":""}`, 0, "")
	if err != nil {
		t.Fatalf("create with upper-case type: %v", err)
	}
	if row.Type != config.LoggingSplunk {
		t.Errorf("type not normalized: got %q want %q", row.Type, config.LoggingSplunk)
	}
}

func TestCreateValidatesTypeAndConfig(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.Create("good", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"t","host":"h","index":"i"}`, 0, ""); err != nil {
		t.Fatalf("valid create: %v", err)
	}

	if _, err := m.Create("bad-type", "nope", true, 0, `{}`, 0, ""); !errors.Is(err, ErrInvalidSinkType) {
		t.Fatalf("bad type: got %v, want ErrInvalidSinkType", err)
	}

	if _, err := m.Create("bad-config", config.LoggingSplunk, true, 0, `{not json}`, 0, ""); !errors.Is(err, ErrInvalidSinkConfig) {
		t.Fatalf("bad config: got %v, want ErrInvalidSinkConfig", err)
	}

	if _, err := m.Create("", config.LoggingNone, true, 0, `{}`, 0, ""); err == nil {
		t.Fatalf("empty name should error")
	}
}

func TestCreateAndRoundTrip(t *testing.T) {
	m := newTestManager(t)
	row, err := m.Create("prod-splunk", config.LoggingSplunk, true, 1, `{"url":"http://x","token":"t","host":"h","index":"i"}`, 0, "prod")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if row.Source != SourceDB {
		t.Errorf("Source: got %q want %q", row.Source, SourceDB)
	}

	got, err := m.Get(row.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "prod-splunk" || got.Type != config.LoggingSplunk || !got.Enabled {
		t.Fatalf("get returned wrong row: %+v", got)
	}

	if _, err := m.Get(99999); !errors.Is(err, ErrSinkNotFound) {
		t.Fatalf("missing get: got %v want ErrSinkNotFound", err)
	}
}

func TestUpdatePreservesAndMerges(t *testing.T) {
	m := newTestManager(t)
	row, err := m.Create("s", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"secret","host":"h","index":"i"}`, 0, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := m.Update(row.ID, "s2", config.LoggingSplunk, false, 5, `{"url":"http://y","token":"***","host":"h2","index":"j"}`, "note")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "s2" || updated.Enabled || updated.Order != 5 || updated.Info != "note" {
		t.Fatalf("updated fields wrong: %+v", updated)
	}
	var cfg map[string]any
	_ = json.Unmarshal([]byte(updated.Config), &cfg)
	if cfg["token"] == "secret" {
		t.Fatalf("update did not overwrite config (token should have been replaced with the literal *** the test sent)")
	}
	if cfg["url"] != "http://y" {
		t.Fatalf("update did not overwrite config url: %v", cfg["url"])
	}
}

func TestDelete(t *testing.T) {
	m := newTestManager(t)
	row, err := m.Create("s", config.LoggingNone, true, 0, `{}`, 0, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.Delete(row.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m.Delete(row.ID); !errors.Is(err, ErrSinkNotFound) {
		t.Fatalf("re-delete: got %v want ErrSinkNotFound", err)
	}
}

func TestListByEnvironmentAndEffectiveFor(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("g-none", config.LoggingNone, true, 0, `{}`, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("g-splunk", config.LoggingSplunk, false, 1, `{"url":"","token":"","host":"","index":""}`, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("env5-stdout", config.LoggingStdout, true, 0, `{}`, 5, ""); err != nil {
		t.Fatal(err)
	}

	g, err := m.EffectiveFor(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 2 {
		t.Fatalf("global EffectiveFor(0): got %d want 2", len(g))
	}
	e5, err := m.EffectiveFor(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(e5) != 1 || e5[0].Name != "env5-stdout" {
		t.Fatalf("env 5 override: got %+v", e5)
	}
	e6, err := m.EffectiveFor(6)
	if err != nil {
		t.Fatal(err)
	}
	if len(e6) != 2 {
		t.Fatalf("env 6 fallback to global: got %d want 2", len(e6))
	}
}

func TestCloneEnvironment(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("g-splunk", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"t","host":"h","index":"i"}`, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("g-none", config.LoggingNone, true, 1, `{}`, 0, ""); err != nil {
		t.Fatal(err)
	}

	cloned, err := m.CloneEnvironment(0, 5, false)
	if err != nil {
		t.Fatalf("clone into empty env: %v", err)
	}
	if len(cloned) != 2 {
		t.Fatalf("cloned count: got %d want 2", len(cloned))
	}
	for _, c := range cloned {
		if c.EnvironmentID != 5 {
			t.Errorf("cloned env id: got %d want 5", c.EnvironmentID)
		}
		if c.Source != SourceDB {
			t.Errorf("cloned source: got %q want %q", c.Source, SourceDB)
		}
	}

	if _, err := m.CloneEnvironment(0, 5, false); !errors.Is(err, ErrTargetHasSinks) {
		t.Fatalf("clone into non-empty without overwrite: got %v want ErrTargetHasSinks", err)
	}

	cloned2, err := m.CloneEnvironment(0, 5, true)
	if err != nil {
		t.Fatalf("clone with overwrite: %v", err)
	}
	if len(cloned2) != 2 {
		t.Fatalf("overwrite clone count: got %d want 2", len(cloned2))
	}

	if _, err := m.CloneEnvironment(5, 5, false); err == nil {
		t.Fatalf("clone to same env should error")
	}
	if _, err := m.CloneEnvironment(7, 8, false); err == nil {
		t.Fatalf("clone from empty source should error")
	}
}

func TestSeedIdempotent(t *testing.T) {
	m := newTestManager(t)
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types: []string{config.LoggingNone, config.LoggingStdout},
		},
		DB: &config.YAMLConfigurationDB{Type: "sqlite", FilePath: t.TempDir() + "/p.db"},
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed 1: %v", err)
	}
	rows, err := m.ListByEnvironment(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("seed 1 count: got %d want 2", len(rows))
	}
	for _, r := range rows {
		if r.Source != SourceService {
			t.Errorf("seeded row source: got %q want %q", r.Source, SourceService)
		}
	}

	// Re-seed: must NOT create duplicates or overwrite existing rows.
	// Mutate one row to source=db first to prove it survives.
	if _, err := m.Update(rows[0].ID, rows[0].Name, rows[0].Type, rows[0].Enabled, rows[0].Order, rows[0].Config, rows[0].Info); err != nil {
		t.Fatalf("mark row as db: %v", err)
	}
	gotUpdated, _ := m.Get(rows[0].ID)
	if gotUpdated.Source != SourceDB {
		t.Fatalf("expected row 0 to be source=db after update, got %q", gotUpdated.Source)
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed 2: %v", err)
	}
	rows2, err := m.ListByEnvironment(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 2 {
		t.Fatalf("seed 2 count: got %d want 2 (idempotent)", len(rows2))
	}
	for _, r := range rows2 {
		if r.ID == gotUpdated.ID && r.Source != SourceDB {
			t.Errorf("re-seed overwrote operator-edited row %d (source=%q)", r.ID, r.Source)
		}
	}
}

func TestSeedAlwaysLogInsertsSyntheticDB(t *testing.T) {
	m := newTestManager(t)
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types:     []string{config.LoggingNone},
			AlwaysLog: true,
		},
		DB: &config.YAMLConfigurationDB{Type: "sqlite", FilePath: t.TempDir() + "/p.db"},
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := m.ListByEnvironment(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("alwaysLog: got %d rows want 2 (none + synthetic db)", len(rows))
	}
	var synthetic *LogSink
	for i := range rows {
		if rows[i].Name == "__always_log_db__" {
			synthetic = &rows[i]
		}
	}
	if synthetic == nil {
		t.Fatalf("synthetic __always_log_db__ sink not seeded")
	}
	if synthetic.Type != config.LoggingDB {
		t.Errorf("synthetic type: got %q want %q", synthetic.Type, config.LoggingDB)
	}
}

func TestSeedDBSinkWithLoggerDBSameCopiesPrimaryDetails(t *testing.T) {
	m := newTestManager(t)
	primary := &config.YAMLConfigurationDB{
		Type:     "postgres",
		Host:     "db.example.com",
		Port:     5432,
		Name:     "osctrl",
		Username: "osctrl",
		Password: "secret",
	}
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types:        []string{config.LoggingDB},
			LoggerDBSame: true,
			// logger.db block left at zero — operator expects the
			// primary db: section to be used.
			DB: &config.YAMLConfigurationDB{},
		},
		DB: primary,
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := m.ListByEnvironment(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1 (db)", len(rows))
	}
	var dbCfg config.YAMLConfigurationDB
	if err := json.Unmarshal([]byte(rows[0].Config), &dbCfg); err != nil {
		t.Fatalf("unmarshal db config: %v", err)
	}
	if dbCfg.Host != "db.example.com" {
		t.Errorf("db host: got %q want %q", dbCfg.Host, "db.example.com")
	}
	if dbCfg.Port != 5432 {
		t.Errorf("db port: got %d want 5432", dbCfg.Port)
	}
	if dbCfg.Name != "osctrl" {
		t.Errorf("db name: got %q want %q", dbCfg.Name, "osctrl")
	}
	if dbCfg.Password != "secret" {
		t.Errorf("db password: got %q want %q", dbCfg.Password, "secret")
	}
}

func TestSeedRepairsEmptySeedRowOnReSeed(t *testing.T) {
	// Simulate a previous boot that seeded an empty db row (the bug):
	// manually insert a seed row with an empty config, then re-seed
	// with real values and verify the row is repaired.
	m := newTestManager(t)

	// Insert a stale empty seed row, as if it was created by a
	// previous boot with the LoggerDBSame bug.
	staleRow := LogSink{
		Name:          "seeded-db",
		EnvironmentID: 0,
		Type:          config.LoggingDB,
		Enabled:       true,
		Order:         0,
		Config:        `{"Type":"","Host":"","Port":0,"Name":"","Username":"","Password":"","SSLMode":"","MaxIdleConns":0,"MaxOpenConns":0,"ConnMaxLifetime":0,"ConnRetry":0,"FilePath":""}`,
		Source:        SourceService,
		Info:          "Seeded from service configuration",
	}
	if err := m.DB.Create(&staleRow).Error; err != nil {
		t.Fatalf("create stale row: %v", err)
	}

	// Re-seed with real DB details.
	primary := &config.YAMLConfigurationDB{
		Type: "postgres", Host: "db.example.com", Port: 5432, Name: "osctrl",
	}
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types:        []string{config.LoggingDB},
			LoggerDBSame: true,
			DB:           &config.YAMLConfigurationDB{},
		},
		DB: primary,
	}
	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("re-seed: %v", err)
	}

	rows, _ := m.ListByEnvironment(0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	var dbCfg config.YAMLConfigurationDB
	if err := json.Unmarshal([]byte(rows[0].Config), &dbCfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dbCfg.Host != "db.example.com" {
		t.Fatalf("stale row was not repaired: host=%q", dbCfg.Host)
	}
	if dbCfg.Name != "osctrl" {
		t.Fatalf("stale row was not repaired: name=%q", dbCfg.Name)
	}
	// Source must still be "service" (not "db") — the sync must not
	// flip the source.
	if rows[0].Source != SourceService {
		t.Errorf("sync flipped source to %q", rows[0].Source)
	}
}

func TestSeedDoesNotRepairDBEditedRow(t *testing.T) {
	// A row the operator edited (Source="db") must NOT be touched by
	// re-seed, even if its config is empty.
	m := newTestManager(t)

	editedRow := LogSink{
		Name:          "seeded-db",
		EnvironmentID: 0,
		Type:          config.LoggingDB,
		Enabled:       true,
		Order:         0,
		Config:        `{"Type":"","Host":"","Port":0,"Name":""}`,
		Source:        SourceDB,
		Info:          "operator emptied it on purpose",
	}
	if err := m.DB.Create(&editedRow).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	primary := &config.YAMLConfigurationDB{
		Type: "postgres", Host: "db.example.com", Port: 5432, Name: "osctrl",
	}
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types:        []string{config.LoggingDB},
			LoggerDBSame: true,
			DB:           &config.YAMLConfigurationDB{},
		},
		DB: primary,
	}
	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, _ := m.ListByEnvironment(0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	var dbCfg config.YAMLConfigurationDB
	_ = json.Unmarshal([]byte(rows[0].Config), &dbCfg)
	if dbCfg.Host != "" {
		t.Fatalf("operator-edited row was clobbered: host=%q (want empty)", dbCfg.Host)
	}
	if rows[0].Source != SourceDB {
		t.Errorf("operator-edited row source changed to %q", rows[0].Source)
	}
}

func TestSeedDBSinkWithEmptyLoggerDBFallsBackToPrimary(t *testing.T) {
	m := newTestManager(t)
	primary := &config.YAMLConfigurationDB{
		Type: "sqlite", FilePath: "/tmp/test.db",
	}
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types: []string{config.LoggingDB},
			// logger.db block left at zero, LoggerDBSame is false.
			DB: &config.YAMLConfigurationDB{},
		},
		DB: primary,
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := m.ListByEnvironment(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	var dbCfg config.YAMLConfigurationDB
	if err := json.Unmarshal([]byte(rows[0].Config), &dbCfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dbCfg.Type != "sqlite" || dbCfg.FilePath != "/tmp/test.db" {
		t.Errorf("empty logger.db did not fall back to primary: got %+v", dbCfg)
	}
}

func TestSeedDBSinkWithExplicitLoggerDBUsesIt(t *testing.T) {
	m := newTestManager(t)
	primary := &config.YAMLConfigurationDB{
		Type: "postgres", Host: "primary.example.com", Port: 5432, Name: "osctrl",
	}
	loggerDB := &config.YAMLConfigurationDB{
		Type: "postgres", Host: "logs.example.com", Port: 5433, Name: "osctrl_logs",
	}
	params := &config.ServiceParameters{
		Logger: &config.YAMLConfigurationLogger{
			Types:        []string{config.LoggingDB},
			LoggerDBSame: false,
			DB:           loggerDB,
		},
		DB: primary,
	}

	if err := m.Seed(params, 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, _ := m.ListByEnvironment(0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	var dbCfg config.YAMLConfigurationDB
	if err := json.Unmarshal([]byte(rows[0].Config), &dbCfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dbCfg.Host != "logs.example.com" {
		t.Errorf("expected explicit logger.db host, got %q", dbCfg.Host)
	}
	if dbCfg.Name != "osctrl_logs" {
		t.Errorf("expected explicit logger.db name, got %q", dbCfg.Name)
	}
}

func TestRedactedConfigMasksSecrets(t *testing.T) {
	cfg := `{"url":"http://x","token":"supersecret","host":"h","index":"i"}`
	got := RedactedConfig(config.LoggingSplunk, cfg)
	var obj map[string]any
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("redacted not json: %v", err)
	}
	if obj["token"] != "***" {
		t.Errorf("token not redacted: got %v", obj["token"])
	}
	if obj["url"] != "http://x" {
		t.Errorf("non-secret field changed: url=%v", obj["url"])
	}
}

func TestRedactedConfigLeavesNonSecretTypesAlone(t *testing.T) {
	cfg := `{"host":"h","port":"1234"}`
	if got := RedactedConfig(config.LoggingLogstash, cfg); got != cfg {
		t.Errorf("non-secret type was modified: got %q want %q", got, cfg)
	}
}

func TestMergeSecretsReplacesPlaceholder(t *testing.T) {
	prev := `{"url":"http://x","token":"real-secret","host":"h","index":"i"}`
	next := `{"url":"http://y","token":"***","host":"h2","index":"j"}`
	got, err := MergeSecrets(config.LoggingSplunk, prev, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var obj map[string]any
	_ = json.Unmarshal([]byte(got), &obj)
	if obj["token"] != "real-secret" {
		t.Errorf("merge did not restore secret: got %v", obj["token"])
	}
	if obj["url"] != "http://y" {
		t.Errorf("merge clobbered non-secret: url=%v", obj["url"])
	}
}

func TestMergeSecretsAcceptsNewSecretValue(t *testing.T) {
	prev := `{"url":"http://x","token":"old","host":"h","index":"i"}`
	next := `{"url":"http://y","token":"new","host":"h","index":"i"}`
	got, err := MergeSecrets(config.LoggingSplunk, prev, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var obj map[string]any
	_ = json.Unmarshal([]byte(got), &obj)
	if obj["token"] != "new" {
		t.Errorf("merge did not accept new secret: got %v", obj["token"])
	}
}

func TestBuildExportersSkipsDisabledAndUnknown(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("off", config.LoggingNone, false, 0, `{}`, 0, ""); err != nil {
		t.Fatal(err)
	}
	// Build directly from a row slice with an unknown type and a disabled row.
	rows := []LogSink{
		{Name: "off", Type: config.LoggingNone, Enabled: false, Config: "{}"},
		{Name: "stdout", Type: config.LoggingStdout, Enabled: true, Config: "{}"},
		{Name: "unknown", Type: "nope", Enabled: true, Config: "{}"},
	}
	multi := BuildExporters(rows, nil)
	if multi == nil {
		t.Fatal("BuildExporters returned nil")
	}
	if len(multi.ExporterNames()) != 1 {
		t.Fatalf("exporter names: got %v want [stdout]", multi.ExporterNames())
	}
}

func TestBuildExportersForEnvironmentsGroupsByEnv(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("g", config.LoggingNone, true, 0, `{}`, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("e5", config.LoggingStdout, true, 0, `{}`, 5, ""); err != nil {
		t.Fatal(err)
	}
	got, err := m.BuildExportersForEnvironments(nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("env groups: got %d want 2", len(got))
	}
	if _, ok := got[0]; !ok {
		t.Error("missing global group (key 0)")
	}
	if _, ok := got[5]; !ok {
		t.Error("missing env 5 group")
	}
}
