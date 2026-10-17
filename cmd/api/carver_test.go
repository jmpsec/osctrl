package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/carves"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Startup builds the carver from the resolved carver section. These pin the
// YAML -> ServiceParameters -> carver wiring that once silently dropped S3.
func TestCarverWiringFromYAML(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	tests := []struct {
		name    string
		carver  string
		wantS3  bool
		wantErr string
	}{
		{name: "db", carver: "carver:\n  type: db\n"},
		{name: "s3", carver: "carver:\n  type: s3\n  s3:\n    bucket: carves\n    region: us-east-1\n", wantS3: true},
		{name: "s3 incomplete", carver: "carver:\n  type: s3\n  s3:\n    bucket: carves\n", wantErr: "carver.s3.region"},
		{name: "local", carver: "carver:\n  type: local\n  local:\n    carvesDir: /tmp\n", wantErr: `carver type "local" is not supported`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadYAMLConfiguration(writeTempConfig(t, "service:\n  auth: none\n"+tt.carver))
			if err == nil {
				params := loadedYAMLToServiceParams(cfg, "api.yml")
				db, derr := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
				if derr != nil {
					t.Fatal(derr)
				}
				var c *carves.Carves
				c, err = carves.CreateFileCarvesFromConfig(db, params.Carver)
				if err == nil {
					if c.Carver != tt.name {
						t.Fatalf("carver = %q", c.Carver)
					}
					if (c.S3 != nil) != tt.wantS3 {
						t.Fatalf("S3 carver initialized = %v, want %v", c.S3 != nil, tt.wantS3)
					}
				}
			}
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
