package environments

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The enroll templates are shell embedded in Go string constants, so nothing
// compiles or lints them and a logic bug ships straight to every endpoint.
// That is not hypothetical: the version check here used to be inverted — it
// reinstalled only when a node was AHEAD of the required version and did
// nothing when it was behind, so "keep osquery up to date" silently never
// upgraded anyone.
//
// These tests pull the decision function out of the template and run it under
// /bin/sh, so the assertions are about the shipped text, not a copy of it.

// extractShellFunc returns the body of a POSIX shell function defined in src,
// from "name() {" through its closing brace at column 0.
func extractShellFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, name+"() {")
	if start < 0 {
		t.Fatalf("function %q not found in the template — was it renamed?", name)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("function %q has no closing brace at column 0", name)
	}
	return rest[:end+len("\n}\n")]
}

func TestOsqueryNeedsInstallDecision(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell available")
	}
	fn := extractShellFunc(t, QuickAddScriptShell, "osqueryNeedsInstall")

	cases := []struct {
		name      string
		required  string
		installed string
		want      string
	}{
		{"behind must upgrade", "5.23.1", "5.19.0", "install"},
		{"behind by a patch must upgrade", "5.23.1", "5.23.0", "install"},
		{"exact match is a no-op", "5.23.1", "5.23.1", "skip"},
		{"ahead is left alone, never downgraded", "5.19.0", "5.23.1", "skip"},
		{"nothing installed", "5.23.1", "", "install"},
		{"double-digit minor sorts numerically, not lexically", "5.9.0", "5.10.0", "skip"},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(dir, "decide.sh")
			body := fn + "\nosqueryNeedsInstall \"$1\" \"$2\"\n"
			if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
				t.Fatalf("writing harness: %v", err)
			}
			out, err := exec.Command("sh", script, tc.required, tc.installed).CombinedOutput()
			if err != nil {
				t.Fatalf("running the extracted function: %v (output %q)", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Errorf("required=%s installed=%s: got %q, want %q",
					tc.required, tc.installed, got, tc.want)
			}
		})
	}
}

// TestRPMInstallUsesUpgradeFlag guards the other half of the same bug: `rpm -i`
// fails outright when the package is already present, which is exactly the
// upgrade path, so the RPM branch could never upgrade anything.
func TestRPMInstallUsesUpgradeFlag(t *testing.T) {
	if strings.Contains(QuickAddScriptShell, "rpm -ivh") {
		t.Error("rpm -ivh cannot upgrade an installed package; use rpm -Uvh")
	}
	if !strings.Contains(QuickAddScriptShell, "rpm -Uvh") {
		t.Error("the RPM branch should install or upgrade with rpm -Uvh")
	}
}
