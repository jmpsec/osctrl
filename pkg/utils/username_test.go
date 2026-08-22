package utils

import (
	"strings"
	"testing"
)

func TestSanitizeUsernameAcceptsPlainUsernames(t *testing.T) {
	// The historical shape must keep validating byte-for-byte, including
	// mixed case: folding it would stop existing accounts from matching
	// their stored row.
	good := []string{
		"alice",
		"Alice",
		"alice123",
		"alice-tester",
		"alice_tester",
		"A",
		"123",
		strings.Repeat("a", MaxPlainUsernameLen),
	}
	for _, u := range good {
		if got := SanitizeUsername(u); got != u {
			t.Errorf("expected %q to pass unchanged, got %q", u, got)
		}
	}
}

func TestSanitizeUsernameAcceptsEmails(t *testing.T) {
	good := []string{
		"alice@example.com",
		"alice.tester@example.com",
		"alice+osctrl@example.com",
		"alice_tester@example.co.uk",
		"alice-tester@sub.example.com",
		"a@b.io",
		"first.last%tag@corp-net.example.org",
	}
	for _, u := range good {
		if got := SanitizeUsername(u); got != u {
			t.Errorf("expected %q to pass, got %q", u, got)
		}
	}
}

// IdPs are inconsistent about the casing they emit for the same mailbox.
// Canonicalizing keeps identity from depending on the database's collation.
func TestSanitizeUsernameLowercasesEmails(t *testing.T) {
	cases := map[string]string{
		"Jane@Corp.com":     "jane@corp.com",
		"JANE.DOE@CORP.COM": "jane.doe@corp.com",
		"  Jane@Corp.com  ": "jane@corp.com",
	}
	for in, want := range cases {
		if got := SanitizeUsername(in); got != want {
			t.Errorf("SanitizeUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeUsernameRejectsUnsafeValues(t *testing.T) {
	bad := []string{
		"",                       // empty
		"   ",                    // whitespace only
		strings.Repeat("a", 65),  // plain shape too long
		"alice b",                // space
		"alice;DROP TABLE users", // semicolon
		"alice'OR 1=1",           // quote
		"alice\nadmin",           // newline (audit-log poisoning)
		"alice\x00root",          // NUL
		"alice<script>",          // angle brackets
		"alice%20space",          // pre-decoded url encoding
		"alice/bob",              // slash
		"alice..\\..\\root",      // path traversal
		"alice.tester",           // dot without a domain is not a username
		// Email-shaped values that must still be refused:
		"@example.com",                            // no local part
		"alice@",                                  // no domain
		"alice@@example.com",                      // doubled separator
		".alice@example.com",                      // leading dot in local part
		"alice.@example.com",                      // trailing dot in local part
		"al..ice@example.com",                     // consecutive dots — traversal primitive
		"alice@example",                           // no TLD
		"alice@example.c",                         // TLD too short
		"alice@-example.com",                      // domain label starts with a hyphen
		"alice@example-.com",                      // domain label ends with a hyphen
		"alice@exa mple.com",                      // space in domain
		"alice@example.com/../root",               // traversal after a valid-looking email
		"alice@example.com\nadmin",                // newline after a valid-looking email
		"alice'@example.com",                      // quote in local part
		"alice/bob@example.com",                   // slash in local part
		strings.Repeat("a", 250) + "@example.com", // over the RFC 5321 ceiling
	}
	for _, u := range bad {
		if got := SanitizeUsername(u); got != "" {
			t.Errorf("expected %q to be rejected, got %q", u, got)
		}
	}
}

func TestSanitizeUsernameTrimsWhitespace(t *testing.T) {
	if got := SanitizeUsername("  alice  "); got != "alice" {
		t.Errorf("expected trim to produce %q, got %q", "alice", got)
	}
}

func TestIsEmailUsername(t *testing.T) {
	if !IsEmailUsername("alice@example.com") {
		t.Error("expected an email to be reported as email-shaped")
	}
	if IsEmailUsername("alice") {
		t.Error("expected a plain username not to be reported as email-shaped")
	}
}
