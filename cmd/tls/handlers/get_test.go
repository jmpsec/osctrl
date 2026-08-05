package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/stretchr/testify/assert"
)

type fakeDegradedReader struct {
	degraded bool
}

func (f *fakeDegradedReader) IsDegraded() bool { return f.degraded }

var _ backend.DegradedReader = (*fakeDegradedReader)(nil)

func TestRootHandler(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	h := CreateHandlersTLS()
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.RootHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "💥", rr.Body.String())
}

func TestHealthHandler(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	h := CreateHandlersTLS()
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.HealthHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "✅", rr.Body.String())
}

// TestHealthHandlerDegraded verifies the health endpoint returns
// HTTP 204 (and no body) when the DB health monitor reports the
// backend as degraded.
func TestHealthHandlerDegraded(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	health := &fakeDegradedReader{degraded: true}
	h := CreateHandlersTLS(WithDBHealth(health))
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.HealthHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Empty(t, rr.Body.String())
}

// TestHealthHandlerDegradedReaderNil verifies that wiring a nil
// monitor keeps the legacy 200 behavior (defense in depth — main.go
// already passes nil when the monitor is disabled).
func TestHealthHandlerDegradedReaderNil(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	h := CreateHandlersTLS(WithDBHealth(nil))
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.HealthHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "✅", rr.Body.String())
}

func TestErrorHandler(t *testing.T) {
	req, _ := http.NewRequest("GET", "/error", nil)
	h := CreateHandlersTLS()
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ErrorHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "uh oh...", rr.Body.String())
}
