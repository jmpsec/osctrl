package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
)

func TestHandlerAuthCheckJSONvsRedirect(t *testing.T) {
	// A no-op inner handler — handlerAuthCheck should never call it when
	// there's no valid token. We just need to assert the failure response.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called when auth fails")
	})

	h := handlerAuthCheck(inner, config.AuthJWT, "test-jwt-secret")

	t.Run("Accept application/json returns 401 JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
		req.Header.Set("Accept", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want 401", rr.Code)
		}
		ct := rr.Header().Get("Content-Type")
		if ct == "" || ct[:16] != "application/json" {
			t.Fatalf("Content-Type: got %q, want application/json...", ct)
		}
	})

	t.Run("default client gets 302 redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("status: got %d, want 302", rr.Code)
		}
		if rr.Header().Get("Location") == "" {
			t.Fatal("missing Location header on redirect")
		}
	})
}

func TestExtractHeaderTokenPrefersBearerThenCookie(t *testing.T) {
	cases := []struct {
		name   string
		header string
		cookie string
		want   string
	}{
		{"bearer header", "Bearer abc.def.ghi", "", "abc.def.ghi"},
		{"cookie fallback", "", "xyz.uvw.123", "xyz.uvw.123"},
		{"bearer wins over cookie", "Bearer header-token", "cookie-token", "header-token"},
		{"no auth at all", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: cookieNameToken, Value: tc.cookie})
			}
			got := extractHeaderToken(req)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMutatingMethodsTable(t *testing.T) {
	// Lock the contract that GET/HEAD/OPTIONS bypass CSRF and PUT/PATCH/POST/DELETE require it.
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if mutatingMethods[m] {
			t.Errorf("read-only method %s should not require CSRF", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if !mutatingMethods[m] {
			t.Errorf("mutating method %s must require CSRF", m)
		}
	}
}
