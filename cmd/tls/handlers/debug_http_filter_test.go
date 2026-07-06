package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/assert"
)

// debugCfg is a shorthand builder for the debug-HTTP config used by the
// filter tests.
func debugCfg(enable bool, target string) *config.YAMLConfigurationDebug {
	return &config.YAMLConfigurationDebug{
		EnableHTTP:           enable,
		TargetHostIdentifier: target,
	}
}

func TestShouldDebugHTTPDisabled(t *testing.T) {
	h := &HandlersTLS{DebugHTTPConfig: debugCfg(false, "")}
	assert.False(t, h.shouldDebugHTTP("ABC-123"))
	assert.False(t, h.shouldDebugHTTP(""))
	// The "dump everything" path is also off when debug is disabled.
	assert.False(t, h.debugHTTPAll())
}

func TestShouldDebugHTTPNoFilterDumpsAll(t *testing.T) {
	// Legacy behavior: empty target + EnableHTTP → dump every request,
	// regardless of the node UUID (including unknown/failed lookups).
	h := &HandlersTLS{DebugHTTPConfig: debugCfg(true, "")}
	// shouldDebugHTTP intentionally returns false here; the legacy path is
	// driven by debugHTTPAll() so that malformed/pre-lookup requests are
	// still dumped at the top of the handler.
	assert.False(t, h.shouldDebugHTTP("ABC-123"))
	assert.True(t, h.debugHTTPAll())
}

func TestShouldDebugHTTPFiltered(t *testing.T) {
	h := &HandlersTLS{DebugHTTPConfig: debugCfg(true, "DEADBEEF-1234")}

	// Matching UUID (case-insensitive on both sides).
	assert.True(t, h.shouldDebugHTTP("DEADBEEF-1234"))
	assert.True(t, h.shouldDebugHTTP("deadbeef-1234"))
	assert.True(t, h.shouldDebugHTTP("DeadBeef-1234"))

	// Non-matching UUID never dumps.
	assert.False(t, h.shouldDebugHTTP("CAFE-9999"))

	// Unknown node (empty UUID) never matches a set filter — this is what
	// excludes invalid node_key / anonymous traffic from the filtered
	// dump on a busy server.
	assert.False(t, h.shouldDebugHTTP(""))

	// Filter set ⇒ the legacy "dump everything" path is suppressed.
	assert.False(t, h.debugHTTPAll())
}

func TestShouldDebugHTTPNilConfig(t *testing.T) {
	// Defensive: a handler with no debug config wired must never dump.
	h := &HandlersTLS{}
	assert.False(t, h.shouldDebugHTTP("DEADBEEF-1234"))
	assert.False(t, h.debugHTTPAll())
}
