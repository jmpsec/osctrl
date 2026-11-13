package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

// TestSantaRulesImportExportParity runs the import/export round trip in both
// modes: a dry run stores nothing, an import followed by an export gives the
// same file back, re-importing it is a no-op, and a conflict fails the command.
func TestSantaRulesImportExportParity(t *testing.T) {
	rig := newParityRig(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}
	for i, mode := range []string{"db", "api"} {
		run := map[string]func(...string) (string, error){"db": rig.RunDB, "api": rig.RunAPI}[mode]
		env := rig.SeedEnv("santa" + mode)
		team := []string{"EQHXZ8M8AV", "ABCDE12345"}[i]
		in := write(mode+".json", `[{"identifier":"`+team+`","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"},
			{"identifier":"platform:com.apple.ls","rule_type":"SIGNINGID","policy":"BLOCKLIST","scope":"tag","scope_value":"pilot"}]`)
		count := func() (n int64) {
			require.NoError(t, rig.DB.Model(&santa.Rule{}).Where("environment_id = ?", env.ID).Count(&n).Error)
			return n
		}

		out, err := run("santa", "rules-import", "-e", env.Name, "-f", in, "--dry-run")
		require.NoError(t, err, mode)
		require.Contains(t, out, "new: 2, duplicate: 0, conflicting: 0, invalid: 0", mode)
		require.Zero(t, count(), mode)

		_, err = run("santa", "rules-import", "-e", env.Name, "-f", in)
		require.NoError(t, err, mode)
		require.EqualValues(t, 2, count(), mode)

		exported := filepath.Join(dir, mode+"-export.json")
		_, err = run("santa", "rules-export", "-e", env.Name, "-f", exported)
		require.NoError(t, err, mode)
		out, err = run("santa", "rules-import", "-e", env.Name, "-f", exported)
		require.NoError(t, err, mode)
		require.Contains(t, out, "new: 0, duplicate: 2", mode)
		require.EqualValues(t, 2, count(), mode)

		conflict := write(mode+"-conflict.json", `[{"identifier":"`+team+`","rule_type":"TEAMID","policy":"BLOCKLIST","scope":"env"},
			{"identifier":"ZZZZZ12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}]`)
		out, err = run("santa", "rules-import", "-e", env.Name, "-f", conflict)
		require.ErrorContains(t, err, "nothing imported: 1 conflicting and 0 invalid", mode)
		require.Contains(t, out, "already has policy ALLOWLIST", mode)
		require.EqualValues(t, 2, count(), mode)

		_, err = run("santa", "rules-import", "-e", env.Name, "-f", write(mode+"-bad.json", `{}`))
		require.ErrorContains(t, err, "JSON list of rules", mode)

		var lines []string
		require.NoError(t, rig.DB.Model(&auditlog.AuditLog{}).Where("environment_id = ? AND line LIKE ?", env.ID, "%santa: import rules%").Pluck("line", &lines).Error)
		require.Len(t, lines, 2, mode) // the first import and the no-op re-import
		require.Contains(t, lines[0], "santa: import rules new=2 duplicate=0", mode)
	}
}
