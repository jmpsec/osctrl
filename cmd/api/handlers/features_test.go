package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestFeaturesHandlerReportsFileExplorerOnlyWhenQueryAcceleratedAndEnabled(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  config.YAMLConfigurationOsquery
		want bool
	}{
		{name: "disabled by default", cfg: config.YAMLConfigurationOsquery{}, want: false},
		{name: "requires query", cfg: config.YAMLConfigurationOsquery{Accelerated: true, FileExplorer: true}, want: false},
		{name: "requires accelerated", cfg: config.YAMLConfigurationOsquery{Query: true, FileExplorer: true}, want: false},
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
		})
	}
}
