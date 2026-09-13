package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/config"
)

func TestFeaturesHandlerReportsPostureDisabledByDefault(t *testing.T) {
	h := &HandlersApi{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
	w := httptest.NewRecorder()

	h.FeaturesHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Posture {
		t.Fatalf("posture feature: got true want false")
	}
	if resp.Accelerated {
		t.Fatalf("accelerated feature: got true want false")
	}
	// Alerts defaults off: a nil manager (feature flag disabled) must
	// advertise the SPA-hiding switch.
	if resp.Alerts {
		t.Fatalf("alerts feature: got true want false with nil manager")
	}
	if resp.Events || len(resp.EventTopics) != 0 {
		t.Fatal("events must default off with no advertised topics")
	}
}

func TestFeaturesHandlerReportsServiceConfigEnabled(t *testing.T) {
	h := &HandlersApi{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
	w := httptest.NewRecorder()
	h.FeaturesHandler(w, r)

	var off FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &off); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if off.ServiceConfig {
		t.Fatalf("service config feature: got true want false")
	}

	WithServiceConfigEnabled(true)(h)
	WithLogSinksEnabled(true)(h)
	WithAuthProvidersEnabled(true)(h)
	w = httptest.NewRecorder()
	h.FeaturesHandler(w, r)
	var on FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &on); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !on.ServiceConfig {
		t.Fatalf("service config feature: got false want true")
	}
	if !on.LogSinks {
		t.Fatalf("log_sinks feature: got false want true")
	}
	if !on.AuthProviders {
		t.Fatalf("auth_providers feature: got false want true")
	}
}

func TestFeaturesHandlerReportsPostureEnabled(t *testing.T) {
	h := &HandlersApi{}
	WithPostureEnabled(true)(h)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
	w := httptest.NewRecorder()

	h.FeaturesHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Posture {
		t.Fatalf("posture feature: got false want true")
	}
}

func TestFeaturesHandlerReportsAcceleratedEnabled(t *testing.T) {
	h := &HandlersApi{}
	WithOsqueryValues(config.YAMLConfigurationOsquery{Accelerated: true})(h)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
	w := httptest.NewRecorder()

	h.FeaturesHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Accelerated {
		t.Fatalf("accelerated feature: got false want true")
	}
}

func TestFeaturesHandlerReportsConsoleOnlyWhenQueryAndEnabled(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  config.YAMLConfigurationOsquery
		want bool
	}{
		{name: "disabled by default", cfg: config.YAMLConfigurationOsquery{}, want: false},
		{name: "requires query", cfg: config.YAMLConfigurationOsquery{Console: true}, want: false},
		{name: "does not require accelerated", cfg: config.YAMLConfigurationOsquery{Query: true, Console: true}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := &HandlersApi{}
			WithOsqueryValues(tt.cfg)(h)
			r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
			w := httptest.NewRecorder()

			h.FeaturesHandler(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200", w.Code)
			}
			var resp FeaturesResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Console != tt.want {
				t.Fatalf("console feature: got %t want %t", resp.Console, tt.want)
			}
			if tt.want {
				h.Events = &testEventSource{}
				w = httptest.NewRecorder()
				h.FeaturesHandler(w, r)
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode events: %v", err)
				}
				if !containsFeatureTopic(resp.EventTopics, "console") {
					t.Fatalf("console events topic missing: %v", resp.EventTopics)
				}
			}
		})
	}
}

func TestFeaturesHandlerReportsFileExplorerOnlyWhenQueryAndEnabled(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  config.YAMLConfigurationOsquery
		want bool
	}{
		{name: "disabled by default", cfg: config.YAMLConfigurationOsquery{}, want: false},
		{name: "requires query", cfg: config.YAMLConfigurationOsquery{Accelerated: true, FileExplorer: true}, want: false},
		{name: "does not require accelerated", cfg: config.YAMLConfigurationOsquery{Query: true, FileExplorer: true}, want: true},
		{name: "enabled", cfg: config.YAMLConfigurationOsquery{Query: true, Accelerated: true, FileExplorer: true}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := &HandlersApi{}
			WithOsqueryValues(tt.cfg)(h)
			r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
			w := httptest.NewRecorder()

			h.FeaturesHandler(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200", w.Code)
			}
			var resp FeaturesResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.FileExplorer != tt.want {
				t.Fatalf("file explorer feature: got %t want %t", resp.FileExplorer, tt.want)
			}
			if tt.want {
				h.Events = &testEventSource{}
				w = httptest.NewRecorder()
				h.FeaturesHandler(w, r)
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode events: %v", err)
				}
				if !containsFeatureTopic(resp.EventTopics, "file_explorer") {
					t.Fatalf("file explorer events topic missing: %v", resp.EventTopics)
				}
			}
		})
	}
}

func TestFeaturesHandlerReportsAlertsEventTopicWhenEnabled(t *testing.T) {
	h := &HandlersApi{Alerts: &alerts.Manager{}, Events: &testEventSource{}}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/features", nil)
	w := httptest.NewRecorder()

	h.FeaturesHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp FeaturesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Alerts {
		t.Fatalf("alerts feature: got false want true")
	}
	if !containsFeatureTopic(resp.EventTopics, "alerts") {
		t.Fatalf("alerts events topic missing: %v", resp.EventTopics)
	}
}

func containsFeatureTopic(topics []string, want string) bool {
	for _, topic := range topics {
		if topic == want {
			return true
		}
	}
	return false
}
