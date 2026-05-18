package oidc

import (
	"strings"
	"testing"
)

// TestConfigValidate covers all the error paths. Each case is a
// minimal mutation of a known-good config so the test failure points
// to exactly one field.
func TestConfigValidate(t *testing.T) {
	good := Config{
		IssuerURL:    "https://idp.example/realms/x",
		ClientID:     "osctrl-api",
		ClientSecret: "shhh",
		RedirectURL:  "https://api.example/oidc/cb",
	}

	cases := []struct {
		name      string
		mutate    func(c *Config)
		wantError string // substring of the error message
	}{
		{"happy", func(c *Config) {}, ""},
		{"empty issuer", func(c *Config) { c.IssuerURL = "" }, "IssuerURL"},
		{"whitespace issuer", func(c *Config) { c.IssuerURL = "   " }, "IssuerURL"},
		{"non-http issuer", func(c *Config) { c.IssuerURL = "ftp://x" }, "http(s)"},
		{"issuer no host", func(c *Config) { c.IssuerURL = "https://" }, "no host"},
		{"empty client id", func(c *Config) { c.ClientID = "" }, "ClientID"},
		{"empty secret no pkce", func(c *Config) { c.ClientSecret = "" }, "ClientSecret"},
		{"empty secret with pkce", func(c *Config) { c.ClientSecret = ""; c.UsePKCE = true }, ""},
		{"empty redirect", func(c *Config) { c.RedirectURL = "" }, "RedirectURL"},
		{"non-http redirect", func(c *Config) { c.RedirectURL = "javascript:alert(1)" }, "http(s)"},
		{"redirect no host", func(c *Config) { c.RedirectURL = "https://" }, "no host"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantError)
			}
		})
	}
}

// TestEffectiveScopes locks the scope-normalization behavior:
// - empty → injects default set
// - non-empty without openid → prepends openid
// - non-empty with openid → returns as-is
func TestEffectiveScopes(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty defaults", nil, []string{"openid", "profile", "email"}},
		{"empty slice defaults", []string{}, []string{"openid", "profile", "email"}},
		{"missing openid prepended", []string{"profile", "groups"}, []string{"openid", "profile", "groups"}},
		{"openid already first", []string{"openid", "email"}, []string{"openid", "email"}},
		{"openid middle", []string{"profile", "openid", "email"}, []string{"profile", "openid", "email"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Scopes: tc.input}
			got := c.effectiveScopes()
			if !equalStrings(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// TestEffectiveUsernameClaim locks the claim-fallback policy.
func TestEffectiveUsernameClaim(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", DefaultUsernameClaim},
		{"  ", DefaultUsernameClaim},
		{"preferred_username", "preferred_username"},
		{"email", "email"},
		{"sub", "sub"},
		// Case-folded
		{"EMAIL", "email"},
		{" Sub  ", "sub"},
		// Unknown — passed through verbatim (pickUsername handles the
		// fallback at use-time).
		{"weird_claim", "weird_claim"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := Config{UsernameClaim: tc.input}.effectiveUsernameClaim()
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestEffectiveGroupsClaim — symmetric for the groups claim.
func TestEffectiveGroupsClaim(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"", DefaultGroupsClaim},
		{"  ", DefaultGroupsClaim},
		{"groups", "groups"},
		{"roles", "roles"},
		{"my-custom-claim", "my-custom-claim"},
	}
	for _, tc := range cases {
		got := Config{GroupsClaim: tc.input}.effectiveGroupsClaim()
		if got != tc.want {
			t.Errorf("input %q: got %q want %q", tc.input, got, tc.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}
