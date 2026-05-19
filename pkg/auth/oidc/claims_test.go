package oidc

import (
	"strings"
	"testing"
)

// TestPickUsername covers the claim-selection matrix. Subject is the
// always-available fallback per OIDC spec; tests verify that the
// pickUsername logic prefers the configured claim when present and
// falls back to subject otherwise.
func TestPickUsername(t *testing.T) {
	claims := idTokenClaims{
		Subject:           "sub-uuid-1234",
		PreferredUsername: "alice",
		Email:             "alice@example.com",
		Name:              "Alice Tester",
		GivenName:         "Alice",
		FamilyName:        "Tester",
	}

	cases := []struct {
		configClaim string
		want        string
	}{
		{DefaultUsernameClaim, "alice"},
		{"email", "alice@example.com"},
		{"sub", "sub-uuid-1234"},
		// Unknown claim → falls back to subject.
		{"weird", "sub-uuid-1234"},
		// Empty claim → fallback (the upstream caller should
		// normalize to default first, but be defensive).
		{"", "sub-uuid-1234"},
	}
	for _, tc := range cases {
		t.Run(tc.configClaim, func(t *testing.T) {
			got := pickUsername(claims, nil, tc.configClaim)
			if got != tc.want {
				t.Fatalf("pickUsername(%q): got %q want %q", tc.configClaim, got, tc.want)
			}
		})
	}
}

// TestPickUsernameAbsentClaim — when the configured claim isn't on
// the id_token, we fall back to subject. Test by clearing
// PreferredUsername and asking for it.
func TestPickUsernameAbsentClaim(t *testing.T) {
	claims := idTokenClaims{
		Subject: "sub-uuid-1234",
		// PreferredUsername intentionally empty
	}
	got := pickUsername(claims, nil, DefaultUsernameClaim)
	if got != "sub-uuid-1234" {
		t.Fatalf("absent claim should fall back to sub, got %q", got)
	}
}

// TestPickUsernameCustomClaim — covers the Auth0 / Entra / Okta case
// where the operator picks a non-standard claim (e.g. "nickname",
// "upn", "login"). The typed struct doesn't have a field for it, so
// pickUsername must fall through to the raw claim map.
func TestPickUsernameCustomClaim(t *testing.T) {
	claims := idTokenClaims{Subject: "auth0|hex123"}
	raw := map[string]any{
		"sub":      "auth0|hex123",
		"nickname": "alice",
		"upn":      "alice@corp.local",
	}
	if got := pickUsername(claims, raw, "nickname"); got != "alice" {
		t.Errorf("nickname pick: got %q want alice", got)
	}
	if got := pickUsername(claims, raw, "upn"); got != "alice@corp.local" {
		t.Errorf("upn pick: got %q want alice@corp.local", got)
	}
	// Configured claim absent from raw → fall back to subject.
	if got := pickUsername(claims, raw, "missing_claim"); got != "auth0|hex123" {
		t.Errorf("missing claim fallback: got %q want subject", got)
	}
	// Non-string value (array, object) is skipped → fall back to sub.
	rawBad := map[string]any{
		"nickname": []string{"alice", "bob"},
	}
	if got := pickUsername(claims, rawBad, "nickname"); got != "auth0|hex123" {
		t.Errorf("non-string custom claim should fall back to sub, got %q", got)
	}
	// nil raw map (claims decode failed) → fall back to sub for
	// custom claims (typed fields still work; tested elsewhere).
	if got := pickUsername(claims, nil, "nickname"); got != "auth0|hex123" {
		t.Errorf("nil raw map should fall back to sub, got %q", got)
	}
}

// TestSanitizeUsername — threat T23, T26. The character class is
// strict: only [a-zA-Z0-9_-], length 1..64.
func TestSanitizeUsername(t *testing.T) {
	good := []string{
		"alice",
		"alice123",
		"alice-tester",
		"alice_tester",
		"A",
		"123",
		strings.Repeat("a", 64),
	}
	for _, u := range good {
		if got := sanitizeUsername(u); got != u {
			t.Errorf("expected %q to pass, got %q", u, got)
		}
	}

	bad := []string{
		"",                // empty
		"   ",             // whitespace only
		strings.Repeat("a", 65),     // too long
		"alice@example.com",         // dot, at
		"alice b",                   // space
		"alice;DROP TABLE users",    // semicolon
		"alice'OR 1=1",              // quote
		"alice\nadmin",              // newline (audit-log poisoning T26)
		"alice\x00root",             // NUL
		"alice<script>",             // angle brackets
		"alice%20space",             // url-encoded — we reject pre-decoded too
		"alice/bob",                 // slash
		"alice..\\..\\root",         // path traversal
	}
	for _, u := range bad {
		if got := sanitizeUsername(u); got != "" {
			t.Errorf("expected %q to be rejected, got %q", u, got)
		}
	}
}

// TestSanitizeUsernameLeadingTrailingWhitespace — TrimSpace must
// happen before regex match so " alice " becomes "alice" (good).
func TestSanitizeUsernameWhitespaceTrim(t *testing.T) {
	got := sanitizeUsername("  alice  ")
	if got != "alice" {
		t.Errorf("expected trim to produce %q, got %q", "alice", got)
	}
}
