package workload

import (
	"testing"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/config"
)

func TestBuildDefaultScenariosIncludesTLSAndAPI(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		TLSBaseURL:   "http://tls",
		APIBaseURL:   "http://api",
		APIUsername:  "admin",
		APIPassword:  "secret",
		EnvUUID:      "env-123",
		EnrollSecret: "enroll",
	}

	scenarios := BuildDefaultScenarios(cfg)
	if len(scenarios) == 0 {
		t.Fatal("expected scenarios")
	}

	var foundTLS bool
	var foundAPI bool
	var foundLogin bool
	var foundNodes bool
	for _, scenario := range scenarios {
		switch scenario.Group {
		case GroupTLS:
			foundTLS = true
		case GroupAPI:
			foundAPI = true
		}
		if scenario.Name == "api-login" {
			foundLogin = true
		}
		if scenario.Name == "api-nodes-paged" {
			foundNodes = true
		}
	}

	if !foundTLS || !foundAPI || !foundLogin || !foundNodes {
		t.Fatalf("expected mixed tls/api scenarios, got %+v", scenarios)
	}
}

func TestBuildDefaultScenariosOmitsAuthenticatedAPIScenariosWithoutCredentials(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		TLSBaseURL:   "http://tls",
		APIBaseURL:   "http://api",
		EnvUUID:      "env-123",
		EnrollSecret: "enroll",
	}

	scenarios := BuildDefaultScenarios(cfg)

	for _, scenario := range scenarios {
		if scenario.AuthRequired {
			t.Fatalf("did not expect auth-required API scenario without credentials: %+v", scenario)
		}
	}
}

func TestNewAPILoginPayload(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		APIUsername: "admin",
		APIPassword: "secret",
	}

	payload := NewAPILoginPayload(cfg)
	if payload.Username != "admin" || payload.Password != "secret" || payload.ExpHours != 24 {
		t.Fatalf("unexpected login payload: %+v", payload)
	}
}
