package carves

import (
	"strings"
	"testing"
)

// TestValidCarvePath locks the character allowlist that gates GenCarveQuery.
func TestValidCarvePath(t *testing.T) {
	good := []string{
		"/etc/passwd",
		"/var/log/auth.log",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"/Users/alice/Library/Application_Support/com.example/cfg",
		"/var/log/*.log",
		"/var/log/auth?.log",
	}
	for _, p := range good {
		if !ValidCarvePath(p) {
			t.Errorf("ValidCarvePath(%q): expected true", p)
		}
	}
	bad := []string{
		"",
		"'; SELECT 1; --",
		"/var/log/a'b",
		"/var/log/a;b",
		"/var/log/a b", // space
		"/var/log/a\"b",
		"/var/log/a\nb",
	}
	for _, p := range bad {
		if ValidCarvePath(p) {
			t.Errorf("ValidCarvePath(%q): expected false", p)
		}
	}
}

// TestGenCarveQueryShape sanity-checks the SQL shape for both glob and
// exact match. Real callers MUST validate file via ValidCarvePath first;
// this test exercises the happy path only.
func TestGenCarveQueryShape(t *testing.T) {
	q1 := GenCarveQuery("/etc/passwd", false)
	if !strings.Contains(q1, "path = '/etc/passwd'") {
		t.Errorf("exact: got %q", q1)
	}
	q2 := GenCarveQuery("/var/log/*.log", true)
	if !strings.Contains(q2, "path LIKE '/var/log/*.log'") {
		t.Errorf("glob: got %q", q2)
	}
}
