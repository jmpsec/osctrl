package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempTLSConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func TestLoadedYAMLCarriesRateLimits(t *testing.T) {
	const body = `
service:
  auth: none
db:
  type: postgres
redis:
  host: 127.0.0.1
rateLimits:
  enroll:
    burst: 9
    period: 2m
    evictAfter: 12m
    retryAfter: 45
`
	cfg, err := loadYAMLConfiguration(writeTempTLSConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "tls.yml")

	if params.RateLimits == nil {
		t.Fatal("RateLimits params are nil")
	}
	if got := params.RateLimits.Enroll.Burst; got != 9 {
		t.Fatalf("enroll burst = %d, want 9", got)
	}
	if got := params.RateLimits.Enroll.Period; got != 2*time.Minute {
		t.Fatalf("enroll period = %s, want 2m", got)
	}
	if got := params.RateLimits.Enroll.RetryAfter; got != 45 {
		t.Fatalf("enroll retryAfter = %d, want 45", got)
	}
}

func TestSampleTLSConfigLoads(t *testing.T) {
	cfg, err := loadYAMLConfiguration(filepath.Join("..", "..", "deploy", "config", "tls.yml"))
	if err != nil {
		t.Fatalf("load sample tls.yml: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "tls.yml")

	if params.BatchWriter == nil {
		t.Fatal("sample tls.yml did not load batchWriter")
	}
	if params.ConfigEndpoints == nil {
		t.Fatal("sample tls.yml did not load configEndpoints")
	}
	if params.Osquery == nil {
		t.Fatal("sample tls.yml did not load osquery")
	}
}
