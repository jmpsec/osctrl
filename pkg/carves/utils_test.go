package carves

import (
	"strings"
	"testing"
)

// TestGenCarveQueryEscapes confirms that single quotes in the input
// path are doubled in the SQL output, so a CarveLevel operator cannot
// break out of the string literal and pivot to arbitrary osquery
// (e.g. `'; SELECT 1; --`).
func TestGenCarveQueryEscapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		glob    bool
		wantSub string
	}{
		{
			name:    "exact: classic injection becomes literal",
			in:      "'; SELECT 1; --",
			glob:    false,
			wantSub: "path = '''; SELECT 1; --'",
		},
		{
			name:    "exact: single quote inside path is doubled",
			in:      "/var/log/a'b",
			glob:    false,
			wantSub: "path = '/var/log/a''b'",
		},
		{
			name:    "glob: injection in LIKE is also escaped",
			in:      "'; DROP TABLE x; --",
			glob:    true,
			wantSub: "path LIKE '''; DROP TABLE x; --' ESCAPE '\\'",
		},
	}
	for _, tc := range cases {
		got := GenCarveQuery(tc.in, tc.glob)
		if !strings.Contains(got, tc.wantSub) {
			t.Errorf("%s: GenCarveQuery(%q, %v) = %q; want substring %q",
				tc.name, tc.in, tc.glob, got, tc.wantSub)
		}
	}
}

// TestGenCarveQueryLegitimatePaths confirms paths that the old
// regex-based gate would have rejected — Windows paths with spaces,
// macOS Application Support paths, accented characters, parentheses —
// all round-trip through the splice cleanly.
func TestGenCarveQueryLegitimatePaths(t *testing.T) {
	paths := []string{
		`C:\Program Files\Common Files\app.log`,
		`/Library/Application Support/com.example/cfg`,
		`/home/álvaro/notes.txt`,
		`/var/log/(archived)/old.log`,
		`/var/log/auth.log`,
		`C:\Users\bob\Documents\hello world.txt`,
	}
	for _, p := range paths {
		// Exact match
		q := GenCarveQuery(p, false)
		if !strings.HasPrefix(q, "SELECT * FROM carves WHERE carve=1 AND path = '") ||
			!strings.HasSuffix(q, "';") {
			t.Errorf("exact: shape wrong for %q: %q", p, q)
		}
		// Glob form
		gq := GenCarveQuery(p, true)
		if !strings.Contains(gq, "path LIKE '") || !strings.HasSuffix(gq, "' ESCAPE '\\';") {
			t.Errorf("glob: shape wrong for %q: %q", p, gq)
		}
	}
}

// TestGenCarveQueryGlobMapping confirms that '*' and '?' in the input
// are mapped to LIKE wildcards '%' and '_' in glob mode, while any
// pre-existing '%' / '_' / '\' in the path are escaped so they are
// treated as literals.
func TestGenCarveQueryGlobMapping(t *testing.T) {
	cases := []struct {
		in      string
		wantSub string
	}{
		{`/var/log/*.log`, `path LIKE '/var/log/%.log' ESCAPE '\'`},
		{`/var/log/auth?.log`, `path LIKE '/var/log/auth_.log' ESCAPE '\'`},
		// Literal % must be escaped to \% so it isn't treated as wildcard.
		{`/tmp/100%done.txt`, `path LIKE '/tmp/100\%done.txt' ESCAPE '\'`},
		// Literal _ must be escaped to \_.
		{`/tmp/snake_case.txt`, `path LIKE '/tmp/snake\_case.txt' ESCAPE '\'`},
		// Literal backslash must be escaped (Windows paths).
		{`C:\logs\*.log`, `path LIKE 'C:\\logs\\%.log' ESCAPE '\'`},
	}
	for _, tc := range cases {
		got := GenCarveQuery(tc.in, true)
		if !strings.Contains(got, tc.wantSub) {
			t.Errorf("GenCarveQuery(%q, true) = %q; want substring %q", tc.in, got, tc.wantSub)
		}
	}
}

// TestGenCarveQueryShape sanity-checks the SQL shape for the happy
// path on both branches.
func TestGenCarveQueryShape(t *testing.T) {
	q1 := GenCarveQuery("/etc/passwd", false)
	if !strings.Contains(q1, "path = '/etc/passwd'") {
		t.Errorf("exact: got %q", q1)
	}
	q2 := GenCarveQuery("/var/log/*.log", true)
	if !strings.Contains(q2, "path LIKE '/var/log/%.log' ESCAPE '\\'") {
		t.Errorf("glob: got %q", q2)
	}
}
