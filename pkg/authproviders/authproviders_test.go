package authproviders

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *AuthProviderManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&AuthProvider{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return &AuthProviderManager{DB: db}
}

func TestRegistryCoversOIDCAndSAML(t *testing.T) {
	if _, ok := Registry[config.AuthOIDC]; !ok {
		t.Error("Registry missing oidc")
	}
	if _, ok := Registry[config.AuthSAML]; !ok {
		t.Error("Registry missing saml")
	}
}

func TestCreateAndRoundTrip(t *testing.T) {
	m := newTestManager(t)
	row, err := m.Create("test-oidc", config.AuthOIDC, true, `{"IssuerURL":"https://idp","ClientID":"c","ClientSecret":"s","RedirectURL":"https://osctrl/callback"}`, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if row.Source != SourceDB {
		t.Errorf("source: got %q want %q", row.Source, SourceDB)
	}
	got, err := m.Get(row.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "test-oidc" || got.Type != config.AuthOIDC || !got.Enabled {
		t.Fatalf("wrong row: %+v", got)
	}
}

func TestCreateRejectsInvalidType(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("bad", "nope", true, `{}`, ""); !errors.Is(err, ErrInvalidProviderType) {
		t.Fatalf("bad type: got %v want ErrInvalidProviderType", err)
	}
}

func TestDelete(t *testing.T) {
	m := newTestManager(t)
	row, _ := m.Create("s", config.AuthOIDC, true, `{"IssuerURL":"https://i","ClientID":"c","ClientSecret":"s","RedirectURL":"https://r"}`, "")
	if err := m.Delete(row.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m.Delete(row.ID); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("re-delete: got %v want ErrProviderNotFound", err)
	}
}

func TestRevertToService(t *testing.T) {
	m := newTestManager(t)
	row, _ := m.Create("s", config.AuthOIDC, true, `{"IssuerURL":"https://i","ClientID":"c","ClientSecret":"s","RedirectURL":"https://r"}`, "")
	if row.Source != SourceDB {
		t.Fatalf("source: got %q want %q", row.Source, SourceDB)
	}
	if err := m.RevertToService(row.ID); err != nil {
		t.Fatalf("revert: %v", err)
	}
	got, _ := m.Get(row.ID)
	if got.Source != SourceService {
		t.Fatalf("after revert: source=%q want %q", got.Source, SourceService)
	}
	// Idempotent
	if err := m.RevertToService(row.ID); err != nil {
		t.Fatalf("revert again: %v", err)
	}
	// Missing
	if err := m.RevertToService(99999); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("revert missing: got %v want ErrProviderNotFound", err)
	}
}

func TestRedactedConfigMasksSecrets(t *testing.T) {
	cfg := `{"IssuerURL":"https://idp","ClientID":"c","ClientSecret":"supersecret","RedirectURL":"https://r"}`
	got := RedactedConfig(config.AuthOIDC, cfg)
	var obj map[string]any
	_ = json.Unmarshal([]byte(got), &obj)
	if obj["ClientSecret"] != "***" {
		t.Errorf("secret not redacted: got %v", obj["ClientSecret"])
	}
	if obj["IssuerURL"] != "https://idp" {
		t.Errorf("non-secret changed: %v", obj["IssuerURL"])
	}
}

func TestMergeSecretsReplacesPlaceholder(t *testing.T) {
	prev := `{"IssuerURL":"https://idp","ClientID":"c","ClientSecret":"real-secret","RedirectURL":"https://r"}`
	next := `{"IssuerURL":"https://idp2","ClientID":"c2","ClientSecret":"***","RedirectURL":"https://r2"}`
	got, err := MergeSecrets(config.AuthOIDC, prev, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var obj map[string]any
	_ = json.Unmarshal([]byte(got), &obj)
	if obj["ClientSecret"] != "real-secret" {
		t.Errorf("secret not restored: got %v", obj["ClientSecret"])
	}
	if obj["IssuerURL"] != "https://idp2" {
		t.Errorf("non-secret clobbered: %v", obj["IssuerURL"])
	}
}

func TestSeedCreatesOIDCRow(t *testing.T) {
	m := newTestManager(t)
	params := &config.ServiceParameters{
		OIDC: &config.YAMLConfigurationOIDC{
			Enabled:      true,
			IssuerURL:    "https://idp.example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://osctrl/callback",
		},
	}
	if err := m.Seed(params); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, _ := m.List()
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	if rows[0].Type != config.AuthOIDC {
		t.Errorf("type: got %q want %q", rows[0].Type, config.AuthOIDC)
	}
	if rows[0].Source != SourceService {
		t.Errorf("source: got %q want %q", rows[0].Source, SourceService)
	}
}

func TestSeedDoesNotCreateDisabledOIDC(t *testing.T) {
	m := newTestManager(t)
	params := &config.ServiceParameters{
		OIDC: &config.YAMLConfigurationOIDC{Enabled: false},
	}
	if err := m.Seed(params); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, _ := m.List()
	if len(rows) != 0 {
		t.Fatalf("got %d rows want 0", len(rows))
	}
}

func TestSeedIdempotent(t *testing.T) {
	m := newTestManager(t)
	params := &config.ServiceParameters{
		OIDC: &config.YAMLConfigurationOIDC{Enabled: true, IssuerURL: "https://i", ClientID: "c", ClientSecret: "s", RedirectURL: "https://r"},
	}
	if err := m.Seed(params); err != nil {
		t.Fatalf("seed 1: %v", err)
	}
	if err := m.Seed(params); err != nil {
		t.Fatalf("seed 2: %v", err)
	}
	rows, _ := m.List()
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1 (idempotent)", len(rows))
	}
}
