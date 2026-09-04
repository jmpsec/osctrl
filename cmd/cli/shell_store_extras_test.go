package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/apiclient"
)

// These tests moved here from the old cmd/cli/api_extras_test.go when the HTTP
// client was promoted to pkg/apiclient. They exercise cmd/cli's own store and
// formatting helpers, not the client — the client round-trip tests stayed with
// the client in pkg/apiclient/extras_test.go.

func TestStoreCastErrors(t *testing.T) {
	// dbStore does not implement the console/posture/saved surfaces.
	store := newDBStore()
	if _, err := storeConsole(store); err == nil {
		t.Fatal("expected storeConsole to reject dbStore")
	}
	if _, err := storePosture(store); err == nil {
		t.Fatal("expected storePosture to reject dbStore")
	}
	if _, err := storeSaved(store); err == nil {
		t.Fatal("expected storeSaved to reject dbStore")
	}
}

func TestAPIStoreImplementsExtraSurfaces(t *testing.T) {
	// Pure type-assertion check — no request is ever issued, so a client
	// pointed at an unreachable URL is sufficient.
	api, err := apiclient.CreateAPI(apiclient.JSONConfigurationAPI{
		URL:   "http://127.0.0.1:1",
		Token: "testtoken",
	}, false)
	if err != nil {
		t.Fatalf("CreateAPI: %v", err)
	}
	store := newAPIStore(api)
	if _, err := storeConsole(store); err != nil {
		t.Fatalf("apiStore should implement consoleStore: %v", err)
	}
	if _, err := storePosture(store); err != nil {
		t.Fatalf("apiStore should implement postureStore: %v", err)
	}
	if _, err := storeSaved(store); err != nil {
		t.Fatalf("apiStore should implement savedStore: %v", err)
	}
}

func TestColumnKeysAndIndent(t *testing.T) {
	keys := columnKeys(map[string]any{"b": 1, "a": 2, "c": 3})
	if len(keys) != 3 || keys[0] != "a" || keys[2] != "c" {
		t.Fatalf("columnKeys not sorted: %v", keys)
	}
	if got := indentLines("x\ny", "  "); got != "  x\n  y" {
		t.Fatalf("indentLines: %q", got)
	}
}
