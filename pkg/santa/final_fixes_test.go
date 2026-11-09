package santa

import (
	"strings"
	"testing"

	"buf.build/gen/go/northpolesec/protos/protocolbuffers/go/syncv2"
	"github.com/stretchr/testify/require"
)

func TestValidateRuleNormalizesAndLimits(t *testing.T) {
	base := func() Rule {
		return Rule{RuleType: "BINARY", Identifier: strings.Repeat("a", 64), Policy: "BLOCKLIST", Scope: "env"}
	}
	r := base()
	r.ScopeValue, r.CELExpr = "stray", "stray"
	require.NoError(t, ValidateRule(&r))
	require.Empty(t, r.ScopeValue)
	require.Empty(t, r.CELExpr)

	r = base()
	r.Policy, r.CELExpr = "CEL", "true"
	require.NoError(t, ValidateRule(&r))
	require.Equal(t, "true", r.CELExpr)

	for name, mut := range map[string]func(*Rule){
		"msg":   func(r *Rule) { r.CustomMsg = strings.Repeat("x", 256) },
		"url":   func(r *Rule) { r.CustomURL = "https://" + strings.Repeat("x", 1017) },
		"scope": func(r *Rule) { r.Scope, r.ScopeValue = "tag", strings.Repeat("x", 256) },
	} {
		r := base()
		mut(&r)
		require.ErrorIs(t, ValidateRule(&r), ErrInvalidRule, name)
	}
	r = base()
	r.CustomMsg, r.CustomURL = strings.Repeat("x", 255), "https://"+strings.Repeat("x", 1016)
	require.NoError(t, ValidateRule(&r))
}

func TestRuleDownloadRulesChangedMidSync(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	require.NoError(t, m.CreateRule(testRule(1)))
	_, err := m.RuleDownload(n, &syncv2.RuleDownloadRequest{})
	require.ErrorIs(t, err, ErrRulesChanged)
}
