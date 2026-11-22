package users

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	envA = "11111111-1111-1111-1111-111111111111"
	envB = "22222222-2222-2222-2222-222222222222"
)

func TestValidateGroupMappings(t *testing.T) {
	known := func(uuid string) bool { return uuid == envA || uuid == envB }
	ok := []GroupMapping{
		{Group: "sec", Roles: []string{"read_only_admin", "alert_admin"}, Environments: []GroupEnvAccess{{Environment: envA, User: true, QueryTier: "full"}}},
		{Group: "it", Environments: []GroupEnvAccess{{Environment: envB, CarveTier: "standard", Admin: true}}},
	}
	require.NoError(t, ValidateGroupMappings(ok, known))
	for name, ms := range map[string][]GroupMapping{
		"superuser":         {{Group: "x", Roles: []string{"superuser"}}},
		"admin":             {{Group: "x", Roles: []string{"admin"}}},
		"unknown env":       {{Group: "x", Environments: []GroupEnvAccess{{Environment: "nope", User: true}}}},
		"tags tier":         {{Group: "x", Environments: []GroupEnvAccess{{Environment: envA, QueryTier: "tags"}}}},
		"duplicate group":   {{Group: "x"}, {Group: "x"}},
		"duplicate env":     {{Group: "x", Environments: []GroupEnvAccess{{Environment: envA}, {Environment: envA}}}},
		"empty group":       {{Group: ""}},
		"newline in group":  {{Group: "sec\nfake audit line"}},
		"none tier by name": {{Group: "x", Environments: []GroupEnvAccess{{Environment: envA, CarveTier: "none"}}}},
	} {
		require.ErrorIs(t, ValidateGroupMappings(ms, known), ErrInvalidGroupMapping, name)
	}
}

func TestSyncGroupAccess(t *testing.T) {
	m := roleTestManager(t)
	for _, u := range []string{"alice", "bob"} {
		acct, err := m.New(u, "", u+"@example.com", u, false, false)
		require.NoError(t, err)
		require.NoError(t, m.Create(acct))
	}
	require.NoError(t, m.SetGroupMappings([]GroupMapping{
		{Group: "sec", Roles: []string{"read_only_admin"}, Environments: []GroupEnvAccess{{Environment: envA, User: true, QueryTier: "standard"}}},
		{Group: "sec-leads", Environments: []GroupEnvAccess{{Environment: envA, QueryTier: "full", Admin: true}}},
	}, "root"))
	sync := func(user string, groups ...string) []string {
		t.Helper()
		changes, err := m.SyncGroupAccess(user, groups)
		require.NoError(t, err)
		out := []string{}
		for _, c := range changes {
			out = append(out, c.String())
		}
		return out
	}
	access := func(user string) (AdminUser, EnvAccess) {
		t.Helper()
		u, err := m.Get(user)
		require.NoError(t, err)
		a, _ := m.GetEnvAccess(user, envA)
		return u, a
	}

	// Joining a mapped group grants its access, and nothing is granted twice.
	require.Equal(t, []string{
		"grant alice env:" + envA + ":query=standard",
		"grant alice env:" + envA + ":user=true",
		"grant alice role:read_only_admin=true",
	}, sync("alice", "sec", "unmapped"))
	u, a := access("alice")
	require.True(t, u.ReadOnlyAdmin)
	require.False(t, u.Admin, "superuser is never granted")
	require.True(t, a.User)
	require.Equal(t, "standard", a.QueryTier)
	require.Empty(t, sync("alice", "sec", "unmapped"))

	// A second group raises the tier; leaving it lowers it back.
	require.Equal(t, []string{
		"grant alice env:" + envA + ":admin=true",
		"change alice env:" + envA + ":query=full (was standard)",
	}, sync("alice", "sec", "sec-leads"))
	require.Equal(t, []string{
		"revoke alice env:" + envA + ":admin (was true)",
		"change alice env:" + envA + ":query=standard (was full)",
	}, sync("alice", "sec"))

	// Leaving every mapped group revokes only what the mappings granted.
	require.Equal(t, []string{
		"revoke alice env:" + envA + ":query (was standard)",
		"revoke alice env:" + envA + ":user (was true)",
		"revoke alice role:read_only_admin (was true)",
	}, sync("alice"))
	u, a = access("alice")
	require.False(t, u.ReadOnlyAdmin)
	require.False(t, a.User)
	require.Equal(t, "none", a.QueryTier)

	// Access granted by hand is left alone, while in the group and after.
	require.NoError(t, m.SetRoles("bob", RoleSet{ReadOnlyAdmin: ptr(true)}))
	require.NoError(t, m.SetEnvTier("bob", envA, QueryLevel, TierFull))
	require.Equal(t, []string{"grant bob env:" + envA + ":user=true"}, sync("bob", "sec"))
	require.Equal(t, []string{"revoke bob env:" + envA + ":user (was true)"}, sync("bob"))
	u, a = access("bob")
	require.True(t, u.ReadOnlyAdmin)
	require.Equal(t, "full", a.QueryTier)

	// A grant an admin changed by hand becomes theirs: kept when the user leaves.
	sync("alice", "sec")
	require.NoError(t, m.SetEnvTier("alice", envA, QueryLevel, TierTags))
	require.Empty(t, sync("alice", "sec"), "the hand change is not undone")
	require.Equal(t, []string{
		"revoke alice env:" + envA + ":user (was true)",
		"revoke alice role:read_only_admin (was true)",
	}, sync("alice"))
	_, a = access("alice")
	require.Equal(t, "tags", a.QueryTier)

	// A mapping change applies at the next sync, with the stored groups.
	sync("alice", "sec")
	require.NoError(t, m.SetGroupMappings([]GroupMapping{{Group: "sec", Roles: []string{"alert_admin"}}}, "root"))
	stored, err := m.GroupAccessUsers()
	require.NoError(t, err)
	require.Len(t, stored, 2)
	require.Equal(t, []string{"sec"}, stored[0].Groups)
	require.Equal(t, []string{
		"revoke alice env:" + envA + ":user (was true)",
		"grant alice role:alert_admin=true",
		"revoke alice role:read_only_admin (was true)",
	}, sync("alice", stored[0].Groups...))

	// A deleted account loses its stored groups and grants.
	require.NoError(t, m.Delete("alice"))
	require.Empty(t, sync("alice", "sec"))
	stored, err = m.GroupAccessUsers()
	require.NoError(t, err)
	require.Len(t, stored, 1)
	var n int64
	require.NoError(t, m.DB.Model(&GroupGrant{}).Where("username = ?", "alice").Count(&n).Error)
	require.Zero(t, n)
}
