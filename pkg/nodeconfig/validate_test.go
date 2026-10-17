package nodeconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		override string
		wantErr  string // empty means valid; otherwise substring of the error
	}{
		{"empty object", `{}`, ""},
		{"option", `{"options":{"verbose":true}}`, ""},
		{"schedule", `{"schedule":{"q":{"query":"select 1","interval":60}}}`, ""},
		{"file paths", `{"file_paths":{"etc":["/etc/%%"]}}`, ""},
		{"empty string", ``, "invalid"},
		{"array", `[]`, "object"},
		{"string", `"x"`, "object"},
		{"options array", `{"options":[]}`, "options"},
		{"schedule string", `{"schedule":"x"}`, "schedule"},
		{"packs number", `{"packs":1}`, "packs"},
		{"decorators array", `{"decorators":[]}`, "decorators"},
		{"auto_table_construction bool", `{"auto_table_construction":true}`, "auto_table_construction"},
		{"null option", `{"options":{"verbose":null}}`, "options.verbose"},
		{"null query", `{"schedule":{"q":null}}`, "schedule.q"},
		{"null in array", `{"file_paths":{"a":[null]}}`, "file_paths.a"},
		{"protected option", `{"options":{"config_tls_refresh":10}}`, "config_tls_refresh"},
		{"protected exact name", `{"options":{"host_identifier":"x"}}`, "host_identifier"},
		{"protected disable_reenrollment", `{"options":{"disable_reenrollment":true}}`, "disable_reenrollment"},
		{"protected carver endpoint", `{"options":{"carver_start_endpoint":"/x"}}`, "carver_start_endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.override)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestProtectedOption(t *testing.T) {
	// Values are pinned here on purpose, independent of the implementation's slices.
	for _, p := range []string{"config_", "logger_tls_", "distributed_", "enroll_", "tls_"} {
		t.Run("prefix "+p, func(t *testing.T) {
			assert.True(t, ProtectedOption(p+"x"))
		})
	}
	for _, n := range []string{
		"carver_start_endpoint", "carver_continue_endpoint", "config_plugin", "logger_plugin",
		"distributed_plugin", "disable_distributed", "disable_enrollment", "disable_reenrollment", "host_identifier",
		"specified_identifier", "proxy_hostname", "read_max",
	} {
		t.Run("name "+n, func(t *testing.T) {
			assert.True(t, ProtectedOption(n))
		})
	}
	for _, n := range []string{"tls_hostname", "enroll_secret_path", "distributed_interval", "logger_tls_period", "config_refresh"} {
		t.Run("example "+n, func(t *testing.T) {
			assert.True(t, ProtectedOption(n))
		})
	}
	// Exact names do not match longer variants.
	for _, n := range []string{"carver_start_endpoint_x", "carver_continue_endpoint_x", "host_identifier_x", "read_max_x", "proxy_hostname_x"} {
		t.Run("exact only "+n, func(t *testing.T) {
			assert.False(t, ProtectedOption(n))
		})
	}
	for _, n := range []string{"verbose", "logger_snapshot_event_type", "disable_events", "carver_block_size", "schedule_splay_percent"} {
		t.Run("allowed "+n, func(t *testing.T) {
			assert.False(t, ProtectedOption(n))
		})
	}
	t.Run("case sensitive", func(t *testing.T) {
		assert.False(t, ProtectedOption("TLS_hostname"))
	})
}
