package handlers

import (
	"context"
	"testing"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestVisibleScope(t *testing.T) {
	h := setupUserAdd(t)
	const env = "uuid-dev"
	mk := func(u users.AdminUser) {
		require.NoError(t, h.Users.Create(u))
	}
	mk(users.AdminUser{Username: "plain"})
	mk(users.AdminUser{Username: "tagger"})
	mk(users.AdminUser{Username: "ro", ReadOnlyAdmin: true})
	mk(users.AdminUser{Username: "eadmin"})
	mk(users.AdminUser{Username: "nobody"})
	set := func(u string, l users.AccessLevel, v bool) {
		require.NoError(t, h.Users.SetEnvLevel(u, env, l, v))
	}
	set("plain", users.UserLevel, true)
	require.NoError(t, h.Users.SetEnvTier("plain", env, users.QueryLevel, users.TierTags))
	require.NoError(t, h.Users.SetEnvTier("tagger", env, users.QueryLevel, users.TierTags))
	require.NoError(t, h.Users.SetScopeTags("tagger", env, "root", []uint{7}))
	set("eadmin", users.AdminLevel, true)

	cases := []struct {
		user string
		want users.Tier
		tags []uint
	}{
		{"plain", users.TierStandard, nil},
		{"tagger", users.TierTags, []uint{7}},
		{"ro", users.TierStandard, nil},
		{"eadmin", users.TierFull, nil},
		{"root", users.TierFull, nil},
		{"nobody", users.TierNone, nil},
	}
	for _, c := range cases {
		t.Run(c.user, func(t *testing.T) {
			s, err := h.visibleScope(context.Background(), c.user, env)
			require.NoError(t, err)
			require.Equal(t, c.want, s.Tier)
			require.Equal(t, c.tags, s.TagIDs)
		})
	}
}
