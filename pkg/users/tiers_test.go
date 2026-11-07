package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

const tEnv = "env-1"

func tierUser(t *testing.T, u AdminUser) *UserManager {
	m := roleTestManager(t)
	require.NoError(t, m.Create(u))
	return m
}

func TestTierContextLegacyRowIsStandard(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u"})
	require.NoError(t, m.SetEnvQuery("u", tEnv, true))
	ctx := context.Background()
	require.Equal(t, TierStandard, m.TierContext(ctx, "u", tEnv, QueryLevel))
	require.Equal(t, TierNone, m.TierContext(ctx, "u", tEnv, CarveLevel))
}

func TestTierContextAdminIsFull(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "a"})
	require.NoError(t, m.SetEnvAdmin("a", tEnv, true))
	require.NoError(t, m.Create(AdminUser{Username: "root", Admin: true}))
	for _, ctx := range []context.Context{context.Background(), WithPermissionCache(context.Background())} {
		for _, u := range []string{"a", "root"} {
			require.Equal(t, TierFull, m.TierContext(ctx, u, tEnv, QueryLevel))
			require.Equal(t, TierFull, m.TierContext(ctx, u, tEnv, CarveLevel))
		}
	}
}

func TestSetEnvTierRoundTrip(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u"})
	require.NoError(t, m.SetEnvTier("u", tEnv, QueryLevel, TierTags))
	require.Equal(t, TierTags, m.TierContext(context.Background(), "u", tEnv, QueryLevel))
	require.True(t, m.CheckPermissions("u", QueryLevel, tEnv))
	require.NoError(t, m.SetEnvTier("u", tEnv, CarveLevel, TierNone))
	require.False(t, m.CheckPermissions("u", CarveLevel, tEnv))
}

func TestLegacyWriteAfterTier(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u"})
	ctx := context.Background()
	require.NoError(t, m.SetEnvTier("u", tEnv, QueryLevel, TierTags))
	require.NoError(t, m.SetEnvQuery("u", tEnv, false))
	require.Equal(t, TierNone, m.TierContext(ctx, "u", tEnv, QueryLevel))
	require.NoError(t, m.SetEnvQuery("u", tEnv, true))
	require.Equal(t, TierStandard, m.TierContext(ctx, "u", tEnv, QueryLevel))
	require.NoError(t, m.SetEnvTier("u", tEnv, QueryLevel, TierFull))
	require.NoError(t, m.SetEnvQuery("u", tEnv, true))
	require.Equal(t, TierFull, m.TierContext(ctx, "u", tEnv, QueryLevel))
}

func TestParseTier(t *testing.T) {
	for _, n := range []string{"none", "tags", "standard", "full"} {
		got, err := ParseTier(n)
		require.NoError(t, err)
		require.Equal(t, n, got.String())
	}
	for _, n := range []string{"", "admin"} {
		_, err := ParseTier(n)
		require.Error(t, err)
	}
}

func TestReadOnlyPassesUserLevel(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u", ReadOnlyAdmin: true})
	for _, ctx := range []context.Context{context.Background(), WithPermissionCache(context.Background())} {
		require.True(t, m.CheckPermissionsContext(ctx, "u", UserLevel, tEnv))
		require.False(t, m.CheckPermissionsContext(ctx, "u", QueryLevel, tEnv))
		require.False(t, m.CheckPermissionsContext(ctx, "u", AdminLevel, tEnv))
	}
	require.True(t, m.CheckPermissions("u", UserLevel, tEnv))
	require.False(t, m.CheckPermissions("u", QueryLevel, tEnv))
	require.False(t, m.CheckPermissions("u", AdminLevel, tEnv))
}

func TestGetAccessIncludesTiers(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u"})
	require.NoError(t, m.SetEnvTier("u", tEnv, QueryLevel, TierTags))
	acc, err := m.GetAccess("u")
	require.NoError(t, err)
	require.True(t, acc[tEnv].Query)
	require.Equal(t, "tags", acc[tEnv].QueryTier)
	require.Equal(t, "none", acc[tEnv].CarveTier)
	ea, err := m.GetEnvAccess("u", tEnv)
	require.NoError(t, err)
	require.Equal(t, "tags", ea.QueryTier)
}

// The UI reloads GetEnvAccess and toggles only the bools; the bool must win.
func TestChangeAccessBoolBeatsReloadedTier(t *testing.T) {
	m := tierUser(t, AdminUser{Username: "u"})
	ctx := context.Background()
	require.NoError(t, m.SetEnvTier("u", tEnv, QueryLevel, TierStandard))
	ea, err := m.GetEnvAccess("u", tEnv)
	require.NoError(t, err)
	ea.Query = false
	require.NoError(t, m.ChangeAccess("u", tEnv, ea))
	require.Equal(t, TierNone, m.TierContext(ctx, "u", tEnv, QueryLevel))

	ea, err = m.GetEnvAccess("u", tEnv)
	require.NoError(t, err)
	require.Equal(t, "none", ea.QueryTier)
	ea.Query = true
	require.NoError(t, m.ChangeAccess("u", tEnv, ea))
	require.Equal(t, TierStandard, m.TierContext(ctx, "u", tEnv, QueryLevel))

	// An explicit tier with the bool set still applies.
	ea.QueryTier = "tags"
	require.NoError(t, m.ChangeAccess("u", tEnv, ea))
	require.Equal(t, TierTags, m.TierContext(ctx, "u", tEnv, QueryLevel))
	// Bool true + tier none keeps the existing tier (legacy rule).
	ea.QueryTier = "none"
	require.NoError(t, m.ChangeAccess("u", tEnv, ea))
	require.Equal(t, TierTags, m.TierContext(ctx, "u", tEnv, QueryLevel))
}
