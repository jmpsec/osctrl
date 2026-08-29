package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
)

// osctrl-api reads its config either from flags/env vars or from a YAML
// file via --config. The YAML path replaces flagParams wholesale, so any
// section loadedYAMLToServiceParams forgets to carry over is silently
// dropped — which is exactly how the SAML/OIDC sections went missing:
// federated login stayed off no matter what the operator configured,
// with no error anywhere. These tests pin the wiring.

const ssoConfigYAML = `
service:
  listener: 127.0.0.1
  port: 9000
  auth: jwt
db:
  type: postgres
jwt:
  jwtSecret: "not-a-real-secret-just-for-parsing"
saml:
  enabled: true
  entityId: https://osctrl.example.com/api/v1/auth/saml/metadata
  acsUrl: https://osctrl.example.com/api/v1/auth/saml/acs
  metadataUrl: https://idp.example.com/realms/osctrl/protocol/saml/descriptor
  usernameAttribute: preferred_username
  jitProvision: true
  forceAuthn: false
oidc:
  enabled: true
  issuerUrl: https://idp.example.com/realms/osctrl
  clientId: osctrl-api
  clientSecret: shhh
  redirectUrl: https://osctrl.example.com/api/v1/auth/oidc/callback
  scopes:
    - openid
    - profile
  usernameClaim: nickname
  requiredGroups:
    - osctrl-admins
  jitProvision: true
  usePKCE: true
`

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func TestLoadedYAMLCarriesSSOSections(t *testing.T) {
	cfg, err := loadYAMLConfiguration(writeTempConfig(t, ssoConfigYAML))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "api.yml")

	if params.OIDC == nil {
		t.Fatal("OIDC params are nil — the oidc section was dropped")
	}
	if params.SAML == nil {
		t.Fatal("SAML params are nil — the saml section was dropped")
	}

	// main.go gates provider init on Enabled; if it doesn't survive the
	// round-trip, the routes are never registered and /auth/methods
	// advertises password-only.
	if !params.OIDC.Enabled {
		t.Error("OIDC.Enabled = false, want true")
	}
	if !params.SAML.Enabled {
		t.Error("SAML.Enabled = false, want true")
	}

	if got, want := params.OIDC.IssuerURL, "https://idp.example.com/realms/osctrl"; got != want {
		t.Errorf("OIDC.IssuerURL = %q, want %q", got, want)
	}
	if got, want := params.OIDC.ClientID, "osctrl-api"; got != want {
		t.Errorf("OIDC.ClientID = %q, want %q", got, want)
	}
	if got, want := params.OIDC.UsernameClaim, "nickname"; got != want {
		t.Errorf("OIDC.UsernameClaim = %q, want %q", got, want)
	}
	if !params.OIDC.UsePKCE {
		t.Error("OIDC.UsePKCE = false, want true")
	}
	if got, want := len(params.OIDC.Scopes), 2; got != want {
		t.Errorf("len(OIDC.Scopes) = %d, want %d", got, want)
	}
	if got, want := len(params.OIDC.RequiredGroups), 1; got != want {
		t.Errorf("len(OIDC.RequiredGroups) = %d, want %d", got, want)
	}

	// EntityID and ACSURL are passed to InitSAML as separate arguments,
	// so an empty value here means metadata registration silently
	// mismatches whatever the IdP has on file.
	if got, want := params.SAML.EntityID, "https://osctrl.example.com/api/v1/auth/saml/metadata"; got != want {
		t.Errorf("SAML.EntityID = %q, want %q", got, want)
	}
	if got, want := params.SAML.ACSURL, "https://osctrl.example.com/api/v1/auth/saml/acs"; got != want {
		t.Errorf("SAML.ACSURL = %q, want %q", got, want)
	}
	if got, want := params.SAML.MetaDataURL, "https://idp.example.com/realms/osctrl/protocol/saml/descriptor"; got != want {
		t.Errorf("SAML.MetaDataURL = %q, want %q", got, want)
	}
	if got, want := params.SAML.UsernameAttribute, "preferred_username"; got != want {
		t.Errorf("SAML.UsernameAttribute = %q, want %q", got, want)
	}
	if params.SAML.ForceAuthn {
		t.Error("SAML.ForceAuthn = true, want false — an explicit false must override the default")
	}
}

func TestSAMLForceAuthnDefaultsTrueWhenOmitted(t *testing.T) {
	// forceAuthn is a bool, so an omitted key is indistinguishable from
	// an explicit false once unmarshalled. The --saml-force-authn flag
	// defaults to true; the YAML path has to match it, otherwise "log
	// out" appears not to work — the IdP re-auths from its own cookie.
	const body = `
service:
  auth: jwt
saml:
  enabled: true
  metadataUrl: https://idp.example.com/metadata
`
	cfg, err := loadYAMLConfiguration(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	if !cfg.SAML.ForceAuthn {
		t.Error("SAML.ForceAuthn = false, want true when the key is omitted")
	}
}

func TestLoadedYAMLCarriesRateLimits(t *testing.T) {
	const body = `
service:
  auth: jwt
db:
  type: postgres
redis:
  host: 127.0.0.1
rateLimits:
  login:
    burst: 7
    period: 1m
    evictAfter: 10m
    retryAfter: 23
  preAuth:
    burst: 60
    period: 1m
    evictAfter: 10m
    retryAfter: 60
  serviceConfigApply:
    burst: 3
    period: 10m
    evictAfter: 30m
    retryAfter: 60
`
	cfg, err := loadYAMLConfiguration(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "api.yml")

	if params.RateLimits == nil {
		t.Fatal("RateLimits params are nil")
	}
	if got := params.RateLimits.Login.Burst; got != 7 {
		t.Fatalf("login burst = %d, want 7", got)
	}
	if got := params.RateLimits.Login.Period; got != time.Minute {
		t.Fatalf("login period = %s, want 1m", got)
	}
	if got := params.RateLimits.Login.RetryAfter; got != 23 {
		t.Fatalf("login retryAfter = %d, want 23", got)
	}
}

func TestLoadedYAMLCarriesRedisConfig(t *testing.T) {
	const body = `
service:
  auth: jwt
db:
  type: postgres
redis:
  host: redis.internal
  port: 6380
  password: cache-secret
  connectionString: redis://:url-secret@redis-url.internal:6381/4
  db: 3
  connRetry: 4
`
	cfg, err := loadYAMLConfiguration(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "api.yml")

	if params.Redis == nil {
		t.Fatal("Redis params are nil")
	}
	if got, want := params.Redis.Host, "redis.internal"; got != want {
		t.Errorf("Redis.Host = %q, want %q", got, want)
	}
	if got, want := params.Redis.Port, 6380; got != want {
		t.Errorf("Redis.Port = %d, want %d", got, want)
	}
	if got, want := params.Redis.Password, "cache-secret"; got != want {
		t.Errorf("Redis.Password = %q, want %q", got, want)
	}
	if got, want := params.Redis.ConnectionString, "redis://:url-secret@redis-url.internal:6381/4"; got != want {
		t.Errorf("Redis.ConnectionString = %q, want %q", got, want)
	}
	if got, want := params.Redis.DB, 3; got != want {
		t.Errorf("Redis.DB = %d, want %d", got, want)
	}
	if got, want := params.Redis.ConnRetry, 4; got != want {
		t.Errorf("Redis.ConnRetry = %d, want %d", got, want)
	}
}

func TestSampleAPIConfigLoads(t *testing.T) {
	cfg, err := loadYAMLConfiguration(filepath.Join("..", "..", "deploy", "config", "api.yml"))
	if err != nil {
		t.Fatalf("load sample api.yml: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "api.yml")

	if cfg.Version != config.ConfigVersion {
		t.Fatalf("sample api.yml version = %d, want %d — bump the file when the schema changes", cfg.Version, config.ConfigVersion)
	}
	if params.Osquery == nil {
		t.Fatal("sample api.yml did not load osquery")
	}
	if params.Logger == nil {
		t.Fatal("sample api.yml did not load logger")
	}
	if params.Debug == nil {
		t.Fatal("sample api.yml did not load debug")
	}
	if params.Carver == nil {
		t.Fatal("sample api.yml did not load carver")
	}
}

func TestConfigVersionMismatchDoesNotFailLoad(t *testing.T) {
	// Version skew is a warning, not an error: a file from a newer
	// osctrl release must still load so the service can start (the
	// unknown fields are simply ignored), and a file with no version at
	// all is every pre-existing deployment.
	const body = `
version: 999
service:
  auth: jwt
`
	cfg, err := loadYAMLConfiguration(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration with newer version: %v", err)
	}
	if cfg.Version != 999 {
		t.Fatalf("cfg.Version = %d, want 999", cfg.Version)
	}
}
