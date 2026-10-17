package nodeconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedFlag(t *testing.T) {
	// Values are pinned here on purpose, independent of the implementation's slices.
	prefixes := []string{"tls_", "config_", "logger_tls_", "distributed_tls_", "enroll_"}
	exact := []string{
		"config_plugin", "logger_plugin", "distributed_plugin", "disable_distributed",
		"disable_enrollment", "disable_reenrollment", "host_identifier", "specified_identifier",
		"flagfile", "database_path", "db_path", "carver_start_endpoint", "carver_continue_endpoint",
		"proxy_hostname", "read_max", "force",
	}
	for _, p := range prefixes {
		t.Run("prefix "+p, func(t *testing.T) {
			assert.True(t, ProtectedFlag(p+"x"))
			assert.True(t, ProtectedFlag("no"+p+"x"))
		})
	}
	for _, n := range exact {
		t.Run("name "+n, func(t *testing.T) {
			assert.True(t, ProtectedFlag(n))
			assert.True(t, ProtectedFlag("no"+n))
		})
	}
	for _, n := range []string{"disable_events", "enable_file_events", "audit_allow_process_events", "extensions_autoload", "verbose", "nodes_x", "distributed_interval"} {
		t.Run("allowed "+n, func(t *testing.T) {
			assert.False(t, ProtectedFlag(n))
		})
	}
}

func TestValidateFlagsOverride(t *testing.T) {
	tests := []struct {
		name     string
		override string
		wantErr  string // empty means valid; otherwise substring of the error
	}{
		{"two flags", "--disable_events=false\n--enable_file_events=true", ""},
		{"comment, blank and single dash", "# note\n\n-verbose", ""},
		{"path value", "--extensions_autoload=/etc/osquery/extensions.load", ""},
		{"empty", "", "at least one"},
		{"only comments", "# a\n\n", "at least one"},
		{"no dash", "disable_events=false", "line 1"},
		{"bad name", "--bad name=1", "line 1"},
		{"protected prefix", "--tls_hostname=x", "tls_hostname"},
		{"protected negation", "--noforce", "noforce"},
		{"protected database_path alias", "--db_path=/tmp/x", "db_path"},
		{"duplicate", "--verbose\n--verbose=false", "line 2"},
		{"json", `{"a":1}`, "line 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlagsOverride(tt.override)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMergeFlagsReplacesInPlace(t *testing.T) {
	got, err := MergeFlags("--a=1\n--verbose=false\n--b=2", "-verbose=true")
	require.NoError(t, err)
	assert.Equal(t, "--a=1\n--verbose=true\n--b=2", got)
}

func TestMergeFlagsReplacesEveryOccurrence(t *testing.T) {
	got, err := MergeFlags("--verbose=false\n--a=1\n--verbose=false", "--verbose=true")
	require.NoError(t, err)
	assert.Equal(t, "--verbose=true\n--a=1\n--verbose=true", got)
}

func TestMergeFlagsAppendsInOrder(t *testing.T) {
	got, err := MergeFlags("--a=1", "--z=1\n--m=2")
	require.NoError(t, err)
	assert.Equal(t, "--a=1\n--z=1\n--m=2", got)
}

func TestMergeFlagsBooleanForm(t *testing.T) {
	got, err := MergeFlags("--disable_events=true", "--disable_events=false")
	require.NoError(t, err)
	assert.Equal(t, "--disable_events=false", got)
	got, err = MergeFlags("--verbose", "--verbose=false")
	require.NoError(t, err)
	assert.Equal(t, "--verbose=false", got)
	got, err = MergeFlags("--verbose=false", "--verbose")
	require.NoError(t, err)
	assert.Equal(t, "--verbose", got)
}

func TestMergeFlagsStable(t *testing.T) {
	env := "--a=1\n\n# keep\n--b=2\n"
	over := "# c\n--z=1\n\n--a=9"
	first, err := MergeFlags(env, over)
	require.NoError(t, err)
	second, err := MergeFlags(env, over)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, "--a=9\n\n# keep\n--b=2\n\n--z=1", first)
}

func TestMergeFlagsRejectsInvalid(t *testing.T) {
	_, err := MergeFlags("--a=1", "--tls_hostname=x")
	require.Error(t, err)
	_, err = MergeFlags("--a=1", "")
	require.Error(t, err)
}

func TestFlagOptionConflicts(t *testing.T) {
	got := FlagOptionConflicts("--verbose=true\n--disable_events=false\n--other=1",
		`{"options":{"verbose":false}}`, `{not json`, `{"options":{"disable_events":true}}`, `{"schedule":{}}`)
	assert.Equal(t, []string{"disable_events", "verbose"}, got)
	assert.Empty(t, FlagOptionConflicts("--x=1", `{"options":{"y":1}}`))
}
