package santa

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestValidateRule(t *testing.T) {
	h64 := strings.Repeat("ab", 32)
	h40 := strings.Repeat("cd", 20)
	mk := func(typ, id, pol string) Rule { return Rule{RuleType: typ, Identifier: id, Policy: pol, Scope: "env"} }
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
		wantID  string
	}{
		{"binary", mk("BINARY", h64, "BLOCKLIST"), false, h64},
		{"binary upper normalized", mk("BINARY", strings.ToUpper(h64), "BLOCKLIST"), false, h64},
		{"certificate", mk("CERTIFICATE", h64, "ALLOWLIST"), false, h64},
		{"cdhash", mk("CDHASH", h40, "ALLOWLIST"), false, h40},
		{"teamid", mk("TEAMID", "EQHXZ8M8AV", "ALLOWLIST"), false, "EQHXZ8M8AV"},
		{"teamid lower normalized", mk("TEAMID", "eqhxz8m8av", "ALLOWLIST"), false, "EQHXZ8M8AV"},
		{"signingid", mk("SIGNINGID", "EQHXZ8M8AV:com.google.Chrome", "ALLOWLIST"), false, "EQHXZ8M8AV:com.google.Chrome"},
		{"signingid team uppercased", mk("SIGNINGID", "eqhxz8m8av:com.google.Chrome", "ALLOWLIST"), false, "EQHXZ8M8AV:com.google.Chrome"},
		{"signingid platform", mk("SIGNINGID", "platform:com.apple.curl", "ALLOWLIST"), false, "platform:com.apple.curl"},
		{"cel", Rule{RuleType: "BINARY", Identifier: h64, Policy: "CEL", CELExpr: "true", Scope: "env"}, false, h64},
		{"binary 63 hex", mk("BINARY", h64[:63], "BLOCKLIST"), true, ""},
		{"teamid 9 chars", mk("TEAMID", "eqhxz8m8a", "ALLOWLIST"), true, ""},
		{"signingid no colon", mk("SIGNINGID", "EQHXZ8M8AV", "ALLOWLIST"), true, ""},
		{"signingid empty rest", mk("SIGNINGID", "EQHXZ8M8AV:", "ALLOWLIST"), true, ""},
		{"signingid bad prefix", mk("SIGNINGID", "abc:com.x", "ALLOWLIST"), true, ""},
		{"signingid short prefix", mk("SIGNINGID", "x:y", "ALLOWLIST"), true, ""},
		{"policy REMOVE", mk("BINARY", h64, "REMOVE"), true, ""},
		{"cel empty", mk("BINARY", h64, "CEL"), true, ""},
		{"tag scope empty", Rule{RuleType: "BINARY", Identifier: h64, Policy: "BLOCKLIST", Scope: "tag"}, true, ""},
		{"node scope bad", Rule{RuleType: "BINARY", Identifier: h64, Policy: "BLOCKLIST", Scope: "node", ScopeValue: "nope"}, true, ""},
		{"identifier too long", mk("SIGNINGID", "EQHXZ8M8AV:"+strings.Repeat("a", 256), "ALLOWLIST"), true, ""},
		{"http url", Rule{RuleType: "BINARY", Identifier: h64, Policy: "BLOCKLIST", Scope: "env", CustomURL: "http://x"}, true, ""},
		{"https url", Rule{RuleType: "BINARY", Identifier: h64, Policy: "BLOCKLIST", Scope: "env", CustomURL: "https://x"}, false, h64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule
			err := ValidateRule(&r)
			if tt.wantErr {
				require.Error(t, err)
				require.True(t, errors.Is(err, ErrInvalidRule))
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantID, r.Identifier)
		})
	}
}

func TestValidateRuleNodeUUIDUppercased(t *testing.T) {
	r := Rule{RuleType: "BINARY", Identifier: strings.Repeat("a", 64), Policy: "BLOCKLIST", Scope: "node", ScopeValue: "0a1b2c3d-1111-2222-3333-444455556666"}
	require.NoError(t, ValidateRule(&r))
	require.Equal(t, "0A1B2C3D-1111-2222-3333-444455556666", r.ScopeValue)
}

func TestValidClientMode(t *testing.T) {
	require.True(t, ValidClientMode("MONITOR"))
	require.True(t, ValidClientMode("LOCKDOWN"))
	require.False(t, ValidClientMode("monitor"))
}

func TestMigrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, Migrate(db))
	for _, tbl := range []string{"santa_env_configs", "santa_rules", "santa_machines", "santa_events"} {
		require.True(t, db.Migrator().HasTable(tbl), tbl)
	}
}
