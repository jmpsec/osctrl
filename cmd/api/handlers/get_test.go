package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/assert"
)

type fakeDegradedReader struct {
	degraded bool
}

func (f *fakeDegradedReader) IsDegraded() bool { return f.degraded }

var _ backend.DegradedReader = (*fakeDegradedReader)(nil)

// newHealthTestHandler builds a HandlersApi with the debug-HTTP
// config initialized (the health handler dereferences it for the
// debug dump even when debugging is disabled).
func newHealthTestHandler(opts ...HandlersOption) *HandlersApi {
	opts = append([]HandlersOption{WithDebugHTTP(&config.YAMLConfigurationDebug{})}, opts...)
	return CreateHandlersApi(opts...)
}

// TestHealthHandler_200 verifies the health endpoint returns
// HTTP 200 with the OK body when no DB health monitor is wired
// (the default).
func TestHealthHandler_200(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	h := newHealthTestHandler()
	rr := httptest.NewRecorder()
	http.HandlerFunc(h.HealthHandler).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, okContent, rr.Body.String())
}

// TestHealthHandler_DegradedReturns204 verifies the health
// endpoint returns HTTP 204 (and no body) when the DB health
// monitor reports the backend as degraded.
func TestHealthHandler_DegradedReturns204(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	health := &fakeDegradedReader{degraded: true}
	h := newHealthTestHandler(WithDBHealth(health))
	rr := httptest.NewRecorder()
	http.HandlerFunc(h.HealthHandler).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Empty(t, rr.Body.String())
}

// TestHealthHandler_DegradedReaderNilKeeps200 verifies that wiring
// a nil monitor keeps the legacy 200 behavior (defense in depth —
// main.go already passes nil when the monitor is disabled).
func TestHealthHandler_DegradedReaderNilKeeps200(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	h := newHealthTestHandler(WithDBHealth(nil))
	rr := httptest.NewRecorder()
	http.HandlerFunc(h.HealthHandler).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, okContent, rr.Body.String())
}

// TestHealthHandler_RecoveredReturns200 verifies that when the
// monitor reports the backend recovered, the health endpoint
// returns 200 again.
func TestHealthHandler_RecoveredReturns200(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	health := &fakeDegradedReader{degraded: false}
	h := newHealthTestHandler(WithDBHealth(health))
	rr := httptest.NewRecorder()
	http.HandlerFunc(h.HealthHandler).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, okContent, rr.Body.String())
}
