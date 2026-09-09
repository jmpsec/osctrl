package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/urfave/cli/v3"
)

func TestQueryDispatchTTLConfiguration(t *testing.T) {
	cfg, err := loadYAMLConfiguration(writeTempTLSConfig(t, "service:\n  auth: none\nosquery:\n  queryDispatchTTL: 45s\n"))
	if err != nil {
		t.Fatal(err)
	}
	params := loadedYAMLToServiceParams(cfg, "tls.yml")
	if got := params.Osquery.QueryDispatchTTL; got != 45*time.Second {
		t.Fatalf("YAML queryDispatchTTL = %s, want 45s", got)
	}

	var dispatchFlag *cli.DurationFlag
	for _, flag := range flags {
		if f, ok := flag.(*cli.DurationFlag); ok && f.Name == "query-dispatch-ttl" {
			copy := *f
			dispatchFlag = &copy
		}
	}
	if dispatchFlag == nil {
		t.Fatal("missing query-dispatch-ttl flag")
	}
	if dispatchFlag.Destination != &flagParams.Osquery.QueryDispatchTTL {
		t.Fatal("query-dispatch-ttl flag has wrong destination")
	}
	dispatchFlag.Destination = &params.Osquery.QueryDispatchTTL
	t.Setenv("QUERY_DISPATCH_TTL", "90s")
	command := &cli.Command{Flags: []cli.Flag{dispatchFlag}, Action: func(context.Context, *cli.Command) error { return nil }}
	if err := command.Run(context.Background(), []string{"tls"}); err != nil {
		t.Fatal(err)
	}
	if got := params.Osquery.QueryDispatchTTL; got != 90*time.Second {
		t.Fatalf("environment queryDispatchTTL = %s, want 90s", got)
	}
}

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

func TestLoadedYAMLCarriesRedisConfig(t *testing.T) {
	const body = `
service:
  auth: none
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
	cfg, err := loadYAMLConfiguration(writeTempTLSConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "tls.yml")

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

func TestSampleTLSConfigLoads(t *testing.T) {
	cfg, err := loadYAMLConfiguration(filepath.Join("..", "..", "deploy", "config", "tls.yml"))
	if err != nil {
		t.Fatalf("load sample tls.yml: %v", err)
	}
	params := loadedYAMLToServiceParams(cfg, "tls.yml")

	if cfg.Version != config.ConfigVersion {
		t.Fatalf("sample tls.yml version = %d, want %d — bump the file when the schema changes", cfg.Version, config.ConfigVersion)
	}
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

func TestConfigVersionMismatchDoesNotFailLoad(t *testing.T) {
	// Version skew is a warning, not an error: a file from a newer
	// osctrl release must still load so the service can start (the
	// unknown fields are simply ignored), and a file with no version at
	// all is every pre-existing deployment.
	const body = `
version: 999
service:
  auth: none
db:
  type: postgres
redis:
  host: 127.0.0.1
`
	cfg, err := loadYAMLConfiguration(writeTempTLSConfig(t, body))
	if err != nil {
		t.Fatalf("loadYAMLConfiguration with newer version: %v", err)
	}
	if cfg.Version != 999 {
		t.Fatalf("cfg.Version = %d, want 999", cfg.Version)
	}
}
