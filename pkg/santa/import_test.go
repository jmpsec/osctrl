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
		res, err := m.ImportRules(1, "alice", specs, apply)
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
	res, err := m.ImportRules(1, "alice", clean, false)
	require.NoError(t, err)
	require.Equal(t, ImportResult{New: 4, Duplicate: 1, Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}}, res)
	rules, _ := m.Rules(1)
	require.Len(t, rules, 1, "a dry run stores nothing")

	res, err = m.ImportRules(1, "alice", clean, true)
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
	res, err = m.ImportRules(1, "alice", export, true)
	require.NoError(t, err)
	require.Equal(t, ImportResult{Duplicate: 5, Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}, Applied: true}, res)
	rules, _ = m.Rules(1)
	require.Len(t, rules, 5)
}
