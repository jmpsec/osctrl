package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestErrorHandler(t *testing.T) {
	req, _ := http.NewRequest("GET", "/error", nil)
	h := CreateHandlersTLS()
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ErrorHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "uh oh...", rr.Body.String())
}

