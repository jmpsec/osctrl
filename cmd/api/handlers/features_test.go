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
