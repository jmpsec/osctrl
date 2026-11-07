package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// --alert-admin must produce the same stored role over the DB and API paths,
// and --no-alert-admin must revoke it; add accepts the positive flags too.
func TestUserRoleFlagsParity(t *testing.T) {
	r := newParityRig(t)
	for mode, run := range map[string]func(...string) (string, error){"db": r.RunDB, "api": r.RunAPI} {
		name := "u-" + mode
		_, err := run("user", "add", "-u", name, "--env-manager")
		require.NoError(t, err, mode)
		u, err := r.Users.Get(name)
		require.NoError(t, err)
		require.True(t, u.EnvManager, mode)
		require.False(t, u.AlertAdmin, mode)

		_, err = run("user", "edit", "-u", name, "--alert-admin")
		require.NoError(t, err, mode)
		u, _ = r.Users.Get(name)
		require.True(t, u.AlertAdmin, mode)
		require.True(t, u.EnvManager, mode, "untouched roles stay")

		_, err = run("user", "edit", "-u", name, "--no-alert-admin")
		require.NoError(t, err, mode)
		u, _ = r.Users.Get(name)
		require.False(t, u.AlertAdmin, mode)
		require.True(t, u.EnvManager, mode)
	}
}
