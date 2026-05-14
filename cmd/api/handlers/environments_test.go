package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
)

// TestProjectEnvironmentViewStripsSecrets is the load-bearing regression test
// for the env-secret-containment fix. projectEnvironmentView returns the SPA
// envelope served to UserLevel operators; if a future contributor adds a new
// secret-bearing field to TLSEnvironment without extending the projection,
// the field will leak into the low-priv response. This test marshals the
// projection from a fully-populated source struct and asserts every
// known-sensitive substring is absent from the serialized JSON.
func TestProjectEnvironmentViewStripsSecrets(t *testing.T) {
	src := environments.TLSEnvironment{
		ID:        1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UUID:      "11111111-2222-3333-4444-555555555555",
		Name:      "prod",
		Hostname:  "osctrl.example.com",
		Type:      "dev",
		Icon:      "rocket",
		// The fields below must NOT appear in the projection.
		Secret:           "SECRET-MARKER-enroll",
		EnrollSecretPath: "SECRET-MARKER-enroll-path",
		RemoveSecretPath: "SECRET-MARKER-remove-path",
		Certificate:      "SECRET-MARKER-cert",
		Flags:            "SECRET-MARKER-flags",
		Options:          "SECRET-MARKER-options",
		Schedule:         "SECRET-MARKER-schedule",
		Packs:            "SECRET-MARKER-packs",
		Decorators:       "SECRET-MARKER-decorators",
		ATC:              "SECRET-MARKER-atc",
		Configuration:    "SECRET-MARKER-configuration",
		DebPackage:       "SECRET-MARKER-deb",
		RpmPackage:       "SECRET-MARKER-rpm",
		MsiPackage:       "SECRET-MARKER-msi",
		PkgPackage:       "SECRET-MARKER-pkg",
		EnrollPath:       "SECRET-MARKER-enroll-route",
		LogPath:          "SECRET-MARKER-log-route",
		ConfigPath:       "SECRET-MARKER-config-route",
		QueryReadPath:    "SECRET-MARKER-qread-route",
		QueryWritePath:   "SECRET-MARKER-qwrite-route",
		CarverInitPath:   "SECRET-MARKER-carver-init",
		CarverBlockPath:  "SECRET-MARKER-carver-block",
		UserID:           42,
		// Operational fields that ARE expected in the view:
		ConfigInterval: 60,
		LogInterval:    30,
		QueryInterval:  10,
		AcceptEnrolls:  true,
	}

	view := projectEnvironmentView(src)
	out, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(out)

	// Field set + tag names assertions.
	wantFields := []string{
		`"uuid":"11111111-2222-3333-4444-555555555555"`,
		`"name":"prod"`,
		`"hostname":"osctrl.example.com"`,
		`"icon":"rocket"`,
		`"config_interval":60`,
		`"log_interval":30`,
		`"query_interval":10`,
		`"accept_enrolls":true`,
	}
	for _, w := range wantFields {
		if !strings.Contains(body, w) {
			t.Errorf("expected %q in view JSON, got: %s", w, body)
		}
	}

	// Every SECRET-MARKER must be absent.
	if strings.Contains(body, "SECRET-MARKER") {
		t.Fatalf("view leaked at least one secret-bearing field: %s", body)
	}
}
