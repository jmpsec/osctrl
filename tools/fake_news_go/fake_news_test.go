package main

import (
	"testing"

	internalconfig "github.com/jmpsec/osctrl/tools/fake_news_go/internal/config"
)

func TestDeriveStateFilePerEnvironment(t *testing.T) {
	t.Parallel()

	got := deriveStateFile("fake_news_state.json", "123e4567-e89b-12d3-a456-426614174000", 2)
	want := "fake_news_state_123e4567-e89b-12d3-a456-426614174000.json"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveRuntimeTargetsManual(t *testing.T) {
	t.Parallel()

	targets, err := resolveRuntimeTargets(internalconfig.Config{
		TLSBaseURL:   "http://localhost:9000",
		EnvUUID:      "env-123",
		EnrollSecret: "secret-123",
		StateFile:    "fake_news_state.json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected one target, got %d", len(targets))
	}
	if targets[0].URL != "http://localhost:9000/env-123" {
		t.Fatalf("unexpected target url %q", targets[0].URL)
	}
	if targets[0].StateFile != "fake_news_state.json" {
		t.Fatalf("unexpected state file %q", targets[0].StateFile)
	}
}
