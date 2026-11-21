package santa

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportRules(t *testing.T) {
	m := newTestManager(t)
	hash := strings.Repeat("ab", 32)
	team := RuleSpec{RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "env"}
	require.NoError(t, m.CreateRule(&Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: hash, Policy: "BLOCKLIST", Scope: "env", CreatedBy: "bob"}))
	// the same identifier in another environment is not a conflict
	require.NoError(t, m.CreateRule(&Rule{EnvironmentID: 2, RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "BLOCKLIST", Scope: "env"}))

	specs := []RuleSpec{
		team, // new
		{RuleType: "BINARY", Identifier: strings.ToUpper(hash), Policy: "BLOCKLIST", Scope: "env"},                        // duplicate once normalized
		{RuleType: "TEAMID", Identifier: "eqhxz8m8av", Policy: "ALLOWLIST", Scope: "env"},                                 // duplicate of an earlier import rule
		{RuleType: "BINARY", Identifier: hash, Policy: "ALLOWLIST", Scope: "env"},                                         // conflict: policy
		{RuleType: "BINARY", Identifier: hash, Policy: "BLOCKLIST", Scope: "env", CustomMsg: "no"},                        // conflict: message
		{RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "BLOCKLIST", Scope: "env"},                                 // conflict with an earlier import rule
		{RuleType: "TEAMID", Identifier: "SHORT", Policy: "ALLOWLIST", Scope: "env"},                                      // invalid
		{RuleType: "BINARY", Identifier: hash, Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "pilot"},                    // new: other scope
		{RuleType: "SIGNINGID", Identifier: "platform:com.apple.ls", Policy: "CEL", CELExpr: "true", Scope: "env"},        // new
		{RuleType: "SIGNINGID", Identifier: "platform:com.apple.ls", Policy: "CEL", CELExpr: "false", Scope: "env"},       // conflict: CEL
		{RuleType: "CDHASH", Identifier: strings.Repeat("cd", 20), Policy: "ALLOWLIST", CELExpr: "ignored", Scope: "env"}, // new; CEL dropped
	}

	for _, apply := range []bool{false, true} {
		res, err := m.ImportRules(1, "alice", specs, apply, false)
		require.NoError(t, err)
		require.Equal(t, 4, res.New)
		require.Equal(t, 2, res.Duplicate)
		require.Len(t, res.Conflicts, 4)
		require.Len(t, res.Invalid, 1)
		require.Equal(t, 3, res.Conflicts[0].Index)
		require.Contains(t, res.Conflicts[0].Reason, "policy BLOCKLIST")
		require.Equal(t, 6, res.Invalid[0].Index)
		require.False(t, res.Applied, "conflicts and invalid rules block the import")
		rules, err := m.Rules(1)
		require.NoError(t, err)
		require.Len(t, rules, 1, "nothing is stored")
	}

	clean := []RuleSpec{specs[0], specs[1], specs[7], specs[8], specs[10]}
	res, err := m.ImportRules(1, "alice", clean, false, false)
	require.NoError(t, err)
	require.Equal(t, ImportResult{New: 4, Duplicate: 1, Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}}, res)
	rules, _ := m.Rules(1)
	require.Len(t, rules, 1, "a dry run stores nothing")

	res, err = m.ImportRules(1, "alice", clean, true, false)
	require.NoError(t, err)
	require.True(t, res.Applied)
	require.Equal(t, 4, res.New)
	rules, err = m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 5)
	require.Equal(t, "bob", rules[0].CreatedBy, "the existing rule is untouched")
	require.Equal(t, "alice", rules[1].CreatedBy)
	other, _ := m.Rules(2)
	require.Len(t, other, 1)

	// re-importing an export is a no-op
	export := ExportRules(rules)
	require.Equal(t, "BINARY", export[0].RuleType)
	require.Equal(t, "TEAMID", export[len(export)-1].RuleType)
	res, err = m.ImportRules(1, "alice", export, true, false)
	require.NoError(t, err)
	require.Equal(t, ImportResult{Duplicate: 5, Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}, Applied: true}, res)
	rules, _ = m.Rules(1)
	require.Len(t, rules, 5)
}

func TestImportRulesSkipConflicts(t *testing.T) {
	m := newTestManager(t)
	hex := func(i int) string { return strings.Repeat(string(rune('0'+i)), 64) }
	require.NoError(t, m.CreateRule(&Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: hex(0), Policy: "BLOCKLIST", Scope: "env"}))
	// 10 rules, the first conflicting with the existing BLOCKLIST rule
	specs := make([]RuleSpec, 10)
	for i := range specs {
		specs[i] = RuleSpec{RuleType: "BINARY", Identifier: hex(i), Policy: "ALLOWLIST", Scope: "env"}
	}

	res, err := m.ImportRules(1, "alice", specs, true, false)
	require.NoError(t, err)
	require.False(t, res.Applied, "a conflict blocks the import without skip")

	res, err = m.ImportRules(1, "alice", specs, false, true)
	require.NoError(t, err)
	require.False(t, res.Applied, "dry run")
	require.False(t, res.Blocked())

	res, err = m.ImportRules(1, "alice", specs, true, true)
	require.NoError(t, err)
	require.True(t, res.Applied)
	require.True(t, res.ConflictsSkipped)
	require.Equal(t, 9, res.New)
	require.Len(t, res.Conflicts, 1)
	require.Equal(t, 0, res.Conflicts[0].Index)
	rules, err := m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 10)
	for _, r := range rules {
		if r.Identifier == hex(0) {
			require.Equal(t, "BLOCKLIST", r.Policy, "the existing rule is untouched")
		}
	}

	// invalid rules still block, skip or not
	specs = append(specs, RuleSpec{RuleType: "TEAMID", Identifier: "SHORT", Policy: "ALLOWLIST", Scope: "env"})
	res, err = m.ImportRules(1, "alice", specs, true, true)
	require.NoError(t, err)
	require.False(t, res.Applied)
	require.True(t, res.Blocked())
}

func TestRulesCSV(t *testing.T) {
	specs := []RuleSpec{
		{RuleType: "BINARY", Identifier: strings.Repeat("ab", 32), Policy: "BLOCKLIST", CustomMsg: `=HYPERLINK("x"), "quoted"`, Scope: "env"},
		{RuleType: "SIGNINGID", Identifier: "platform:com.apple.ls", Policy: "CEL", CELExpr: "-1 < 0\nline two", Scope: "tag", ScopeValue: "pilot"},
	}
	var buf strings.Builder
	require.NoError(t, WriteRulesCSV(&buf, specs))
	require.Contains(t, buf.String(), `"'=HYPERLINK(""x""), ""quoted"""`, "formula cells are quoted")
	got, err := ReadRulesCSV(strings.NewReader(buf.String()))
	require.NoError(t, err)
	require.Equal(t, specs, got, "round trip")

	// columns by name, any order, extra columns ignored, Excel BOM accepted
	got, err = ReadRulesCSV(strings.NewReader("\ufeffid,Policy,identifier,rule_type,scope\n7,ALLOWLIST,EQHXZ8M8AV,TEAMID,env\n"))
	require.NoError(t, err)
	require.Equal(t, []RuleSpec{{RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "env"}}, got)

	for name, in := range map[string]string{
		"empty":          "",
		"missing column": "identifier,rule_type\nx,BINARY\n",
		"ragged row":     "identifier,rule_type,policy\nx,BINARY\n",
	} {
		_, err := ReadRulesCSV(strings.NewReader(in))
		require.Error(t, err, name)
	}
	got, err = ReadRulesCSV(strings.NewReader("identifier,rule_type,policy\n"))
	require.NoError(t, err)
	require.Empty(t, got)
}
