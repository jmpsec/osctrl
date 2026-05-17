package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAllowBurst verifies a Limiter allows up to `burst` calls in a single
// window and then refuses the (burst+1)th.
func TestAllowBurst(t *testing.T) {
	l := New(3, time.Second, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("expected Allow #%d to return true", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("expected the burst+1 request to be rejected")
	}
}

// TestAllowSeparateKeys verifies buckets don't bleed between keys.
func TestAllowSeparateKeys(t *testing.T) {
	l := New(2, time.Second, time.Minute)
	l.Allow("a")
	l.Allow("a")
	if l.Allow("a") {
		t.Fatal("key a should be over budget")
	}
	if !l.Allow("b") {
		t.Fatal("key b has its own budget")
	}
}

// TestHTTPMiddleware429s verifies the middleware returns 429 + Retry-After
// when the bucket is empty and calls onReject for telemetry.
func TestHTTPMiddleware429s(t *testing.T) {
	l := New(1, time.Second, time.Minute)
	rejected := 0
	mw := l.HTTPMiddleware(
		func(r *http.Request) string { return "fixed" },
		func(r *http.Request, key string) { rejected++ },
	)
	allowed := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	allowed.ServeHTTP(first, httptest.NewRequest("POST", "/login", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	allowed.ServeHTTP(second, httptest.NewRequest("POST", "/login", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", second.Code)
	}
	if got := second.Header().Get("Retry-After"); got == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	if rejected != 1 {
		t.Fatalf("onReject calls: got %d, want 1", rejected)
	}
}

// TestBucketCapOverflow — once `maxBuckets` is reached, additional
// distinct keys all route through the shared overflow bucket so map
// growth is bounded. Existing keys keep their per-key budget.
func TestBucketCapOverflow(t *testing.T) {
	// burst=1, per=time.Hour — each per-key bucket allows exactly one
	// request before refilling.
	l := NewWithCap(1, time.Hour, time.Minute, 2)

	// Two keys → both get their own bucket and one Allow each.
	if !l.Allow("k1") {
		t.Fatal("k1 first Allow must succeed")
	}
	if !l.Allow("k2") {
		t.Fatal("k2 first Allow must succeed")
	}
	if l.Allow("k1") {
		t.Fatal("k1 second Allow must fail (per-key budget exhausted)")
	}

	// k3 / k4 / k5 are NEW keys past the cap. They all share the
	// overflow bucket (burst 1). The first one consumes the overflow
	// burst; the rest must be denied.
	got := 0
	for _, k := range []string{"k3", "k4", "k5", "k6"} {
		if l.Allow(k) {
			got++
		}
	}
	if got > 1 {
		t.Fatalf("overflow burst must be 1, got %d successful Allows on capped keys", got)
	}

	// Verify the map didn't grow past the cap.
	l.mu.Lock()
	size := len(l.buckets)
	l.mu.Unlock()
	if size > 2 {
		t.Fatalf("bucket map exceeded cap: size=%d, cap=2", size)
	}
}

// TestKeyByIPIgnoresForwardingHeaders is the regression for the
// pentest finding: rotating X-Forwarded-For / X-Real-IP must NOT
// produce different rate-limit keys. The key always derives from the
// TCP peer (RemoteAddr) so an attacker behind an edge proxy that
// appends rather than replaces the XFF chain cannot rotate buckets
// per request to defeat the limiter.
func TestKeyByIPIgnoresForwardingHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		xff  string
		xrip string
	}{
		{"no headers", "", ""},
		{"single XFF", "1.2.3.4", ""},
		{"chained XFF", "1.2.3.4, 5.6.7.8, 9.10.11.12", ""},
		{"X-Real-IP", "", "98.76.54.32"},
		{"both", "1.2.3.4", "98.76.54.32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.RemoteAddr = "203.0.113.5:54321"
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xrip != "" {
				r.Header.Set("X-Real-IP", tc.xrip)
			}
			got := KeyByIP(r)
			if got != "203.0.113.5" {
				t.Fatalf("KeyByIP should ignore forwarding headers, got %q want 203.0.113.5", got)
			}
		})
	}
}

// TestMiddlewareXFFRotationDoesNotBypass is the end-to-end form of the
// regression: even when an attacker rotates X-Forwarded-For across
// requests from the same TCP peer, the limiter must still rate-limit
// after `burst` requests.
func TestMiddlewareXFFRotationDoesNotBypass(t *testing.T) {
	l := New(2, time.Second, time.Minute) // burst=2
	called := 0
	h := l.HTTPMiddleware(KeyByIP, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	doReq := func(xff string) int {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = "203.0.113.5:1234" // same TCP peer every time
		r.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Burst of 2 — both allowed.
	for i := 0; i < 2; i++ {
		if got := doReq("attacker-spoof-" + string(rune('A'+i))); got != http.StatusOK {
			t.Fatalf("request %d should pass within burst, got %d", i+1, got)
		}
	}
	// Burst exhausted. Attacker rotates XFF; should still be 429.
	for i := 0; i < 5; i++ {
		code := doReq("attacker-rotated-" + string(rune('A'+i)))
		if code != http.StatusTooManyRequests {
			t.Fatalf("attacker XFF rotation must not bypass limiter (req %d got %d)", i+1, code)
		}
	}
	if called != 2 {
		t.Fatalf("inner handler called %d times, want 2 (only the burst)", called)
	}
}

