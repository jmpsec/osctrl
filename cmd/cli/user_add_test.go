package main

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// userPerms lists name's permission rows as "env/type/value", sorted.
func userPerms(t *testing.T, r *parityRig, name string) []string {
	t.Helper()
	perms, err := r.Users.GetAllPermissions(name)
	require.NoError(t, err)
	res := []string{}
	for _, p := range perms {
		res = append(res, fmt.Sprintf("%s/%d/%t", p.Environment, p.AccessType, p.AccessValue))
	}
	sort.Strings(res)
	return res
}

// `user add` must store environment UUIDs (never names or ""), and DB and API
// modes must produce the same rows for the same input.
func TestUserAddEnvironmentParity(t *testing.T) {
	r := newParityRig(t)
	dev, err := r.Envs.Get("dev")
	require.NoError(t, err)
	cases := []struct {
		name string
		args []string
		envs []string
	}{
		{"by-name", []string{"-e", "dev"}, []string{dev.UUID}},
		{"by-uuid", []string{"-e", dev.UUID}, []string{dev.UUID}},
		{"no-env", nil, nil},
		{"admin", []string{"-a"}, []string{dev.UUID}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.RunDB(append([]string{"user", "add", "-u", "db-" + c.name}, c.args...)...)
			require.NoError(t, err)
			_, err = r.RunAPI(append([]string{"user", "add", "-u", "api-" + c.name}, c.args...)...)
			require.NoError(t, err)
			dbPerms, apiPerms := userPerms(t, r, "db-"+c.name), userPerms(t, r, "api-"+c.name)
			require.Equal(t, dbPerms, apiPerms)
			seen := map[string]bool{}
			perms, err := r.Users.GetAllPermissions("db-" + c.name)
			require.NoError(t, err)
			for _, p := range perms {
				seen[p.Environment] = true
			}
			got := []string{}
			for e := range seen {
				got = append(got, e)
			}
			if c.envs == nil {
				require.Empty(t, got)
			} else {
				require.ElementsMatch(t, c.envs, got)
			}
		})
	}
}

func TestUserAddUnknownEnvironmentCreatesNoUser(t *testing.T) {
	r := newParityRig(t)
	for mode, run := range map[string]func(...string) (string, error){"db": r.RunDB, "api": r.RunAPI} {
		_, err := run("user", "add", "-u", mode, "-e", "nope")
		require.Error(t, err, mode)
		require.False(t, r.Users.Exists(mode), mode)
	}
}
