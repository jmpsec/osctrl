package handlers

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/stretchr/testify/require"
)

// osctrld refuses to install an osquery package it cannot verify, so what this
// field carries — and when it is deliberately empty — decides whether a fleet
// verifies its downloads or falls back to a per-node digest.

func TestOsquerySHA256FromConfig(t *testing.T) {
	digest := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	h := &HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{SHA256: digest}}
	require.Equal(t, digest, h.osquerySHA256())
}

func TestOsquerySHA256IsTrimmed(t *testing.T) {
	// A digest pasted into YAML picks up whitespace easily, and osctrld
	// compares it against a hex string with no room for either side to trim.
	h := &HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{SHA256: "  abc123\n"}}
	require.Equal(t, "abc123", h.osquerySHA256())
}

func TestOsquerySHA256EmptyWhenUnset(t *testing.T) {
	// Empty is the safe answer, not a failure: osctrld then uses its own
	// --osquery-sha256, or refuses to install. Never invent a digest.
	require.Empty(t, (&HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{}}).osquerySHA256())
	require.Empty(t, (&HandlersTLS{}).osquerySHA256(), "a nil osquery config must not panic")
}

// The osquery version in the verify response is what osctrld installs and
// upgrades to, so a configured pin that the handler ignores means the whole
// fleet quietly tracks whatever osctrl was compiled against.

func TestOsqueryVersionFromConfig(t *testing.T) {
	h := &HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{Version: "5.19.0"}}
	require.Equal(t, "5.19.0", h.osqueryVersion())
	require.NotEqual(t, version.OsqueryVersion, h.osqueryVersion(),
		"a configured pin must win over the build-time version")
}

func TestOsqueryVersionIsTrimmed(t *testing.T) {
	h := &HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{Version: " 5.19.0\n"}}
	require.Equal(t, "5.19.0", h.osqueryVersion())
}

func TestOsqueryVersionFallsBackToBuild(t *testing.T) {
	// Unset and nil both mean "whatever this osctrl ships with" — never empty,
	// which osctrld would compare against an installed version and misjudge.
	require.Equal(t, version.OsqueryVersion,
		(&HandlersTLS{OsqueryValues: &config.YAMLConfigurationOsquery{}}).osqueryVersion())
	require.Equal(t, version.OsqueryVersion, (&HandlersTLS{}).osqueryVersion())
}

// TestVerifyResponseWireFormat pins the JSON contract osctrld parses. The field
// name is matched verbatim by osctrld's own VerifyResponse struct; renaming it
// here silently disables verification on every node.
func TestVerifyResponseWireFormat(t *testing.T) {
	raw, err := json.Marshal(types.VerifyResponse{
		Flags:          "--flag",
		Certificate:    "cert",
		OsqueryVersion: "5.23.1",
		OsquerySHA256:  "abc123",
	})
	require.NoError(t, err)

	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Equal(t, "abc123", wire["osquery_sha256"], "osctrld reads osquery_sha256")
	require.Contains(t, wire, "flags")
	require.Contains(t, wire, "certificate")
	require.Contains(t, wire, "osquery_version")

	// An unset digest still ships the key; osctrld treats "" as "no digest
	// from the server" and falls back. Dropping the key entirely would be
	// equivalent, but pinning the shape keeps the contract explicit.
	raw, err = json.Marshal(types.VerifyResponse{OsqueryVersion: "5.23.1"})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Equal(t, "", wire["osquery_sha256"])
}
