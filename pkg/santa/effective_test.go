package santa

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testUUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

func ident(c string) string { return strings.Repeat(c, 64) }

func mustCreate(t *testing.T, m *Manager, r Rule) {
	t.Helper()
	r.EnvironmentID = 1
	if r.RuleType == "" {
		r.RuleType = "BINARY"
	}
	if r.Policy == "" {
		r.Policy = "BLOCKLIST"
	}
	require.NoError(t, m.CreateRule(&r))
}

func ids(rules []Rule) []string {
	out := []string{}
	for _, r := range rules {
		out = append(out, r.Identifier[:1])
	}
	return out
}

func TestEffectiveRulesScope(t *testing.T) {
	m := newTestManager(t)
	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "env"})
	mustCreate(t, m, Rule{Identifier: ident("b"), Scope: "tag", ScopeValue: "web"})
	mustCreate(t, m, Rule{Identifier: ident("c"), Scope: "node", ScopeValue: testUUID})
	mustCreate(t, m, Rule{Identifier: ident("d"), Scope: "tag", ScopeValue: "db"})

	got, err := m.EffectiveRules(1, strings.ToLower(testUUID), []string{"web"})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, ids(got))

	got, err = m.EffectiveRules(1, "11111111-BBBB-CCCC-DDDD-EEEEEEEEEEEE", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, ids(got))
}

func TestEffectiveRulesPrecedence(t *testing.T) {
	m := newTestManager(t)
	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "env", Policy: "ALLOWLIST"})
	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "tag", ScopeValue: "t1", Policy: "SILENT_BLOCKLIST"})
	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "tag", ScopeValue: "t2", Policy: "ALLOWLIST_COMPILER"})
	got, err := m.EffectiveRules(1, testUUID, []string{"t1", "t2"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "SILENT_BLOCKLIST", got[0].Policy) // lowest ID among tag rules

	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "node", ScopeValue: testUUID, Policy: "BLOCKLIST"})
	got, err = m.EffectiveRules(1, testUUID, []string{"t1", "t2"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "BLOCKLIST", got[0].Policy)
}

func TestEffectiveRulesSorted(t *testing.T) {
	m := newTestManager(t)
	mustCreate(t, m, Rule{Identifier: ident("b"), Scope: "env"})
	mustCreate(t, m, Rule{Identifier: ident("a"), Scope: "env"})
	got, err := m.EffectiveRules(1, testUUID, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, ids(got))
}

func TestRulesDigestStable(t *testing.T) {
	a := Rule{RuleType: "BINARY", Identifier: "a", Policy: "BLOCKLIST"}
	b := Rule{RuleType: "TEAMID", Identifier: "b", Policy: "ALLOWLIST"}
	d := RulesDigest([]Rule{a, b})
	require.Equal(t, d, RulesDigest([]Rule{b, a}))
	a2 := a
	a2.Policy = "ALLOWLIST"
	require.NotEqual(t, d, RulesDigest([]Rule{a2, b}))
	// field boundaries are unambiguous
	require.NotEqual(t,
		RulesDigest([]Rule{{RuleType: "BINARY", Identifier: "a", Policy: "bc"}}),
		RulesDigest([]Rule{{RuleType: "BINARY", Identifier: "ab", Policy: "c"}}))
}
