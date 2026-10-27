package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// permRig seeds users with a known access on dev and returns the dev UUID.
func permRig(t *testing.T, access map[string]users.EnvAccess) (*parityRig, string) {
	t.Helper()
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	for name, a := range access {
		r.SeedUser(name, false)
		require.NoError(t, r.Users.ChangeAccess(name, env.UUID, a))
	}
	return r, env.UUID
}

func (r *parityRig) modes() map[string]func(...string) (string, error) {
	return map[string]func(...string) (string, error){"db": r.RunDB, "api": r.RunAPI}
}

func TestPermissionsShowAllParity(t *testing.T) {
	r, _ := permRig(t, map[string]users.EnvAccess{"bob": {User: true, Carve: true}})
	r.SeedEnv("prod") // bob has no rows here: shown as all-false in both modes
	for _, args := range [][]string{
		{"-o", "json", "user", "show-permissions", "-u", "bob", "-e", "dev"},
		{"-o", "csv", "user", "show-permissions", "-u", "bob", "-e", "dev"},
		{"-o", "json", "user", "show-permissions", "-u", "bob", "-e", "prod"},
		{"-o", "pretty", "user", "show-permissions", "-u", "bob", "-e", "prod"},
		{"-o", "json", "user", "all-permissions", "-u", "bob"},
		{"-o", "csv", "user", "all-permissions", "-u", "bob"},
	} {
		dbOut, err := r.RunDB(args...)
		require.NoError(t, err, args)
		apiOut, err := r.RunAPI(args...)
		require.NoError(t, err, args)
		require.NotEmpty(t, dbOut, args)
		require.Equal(t, dbOut, apiOut, args)
	}
	_, err := r.RunAPI("user", "all-permissions", "-u", "ghost")
	require.Error(t, err)
	_, err = r.RunDB("user", "all-permissions", "-u", "ghost")
	require.Error(t, err)
}

func TestPermissionsResetParity(t *testing.T) {
	r, uuid := permRig(t, map[string]users.EnvAccess{
		"db":  {User: true, Query: true, Carve: true},
		"api": {User: true, Query: true, Carve: true},
	})
	for mode, run := range r.modes() {
		_, err := run("user", "reset-permissions", "-u", mode, "-e", "dev", "-U")
		require.NoError(t, err, mode)
	}
	for _, name := range []string{"db", "api"} {
		got, err := r.Users.GetEnvAccess(name, uuid)
		require.NoError(t, err)
		require.Equal(t, users.EnvAccess{User: true}, got, name)
	}
}

func TestPermissionsChangeIsAdditiveInBothModes(t *testing.T) {
	r, uuid := permRig(t, map[string]users.EnvAccess{
		"db":  {Query: true},
		"api": {Query: true},
	})
	for mode, run := range r.modes() {
		_, err := run("user", "change-permissions", "-u", mode, "-e", "dev", "-U")
		require.NoError(t, err, mode)
		_, err = run("user", "change-permissions", "-u", mode, "-e", "dev", "-c")
		require.NoError(t, err, mode)
		got, err := r.Users.GetEnvAccess(mode, uuid)
		require.NoError(t, err)
		require.Equal(t, users.EnvAccess{User: true, Query: true, Carve: true}, got, mode)
	}
}

func TestPermissionsAdminImpliesAll(t *testing.T) {
	r, uuid := permRig(t, map[string]users.EnvAccess{
		"dbc": {}, "apic": {}, "dbr": {}, "apir": {},
	})
	all := users.EnvAccess{User: true, Query: true, Carve: true, Admin: true}
	for mode, run := range r.modes() {
		_, err := run("user", "change-permissions", "-u", mode+"c", "-e", "dev", "-a")
		require.NoError(t, err, mode)
		_, err = run("user", "reset-permissions", "-u", mode+"r", "-e", "dev", "-a")
		require.NoError(t, err, mode)
		for _, n := range []string{mode + "c", mode + "r"} {
			got, err := r.Users.GetEnvAccess(n, uuid)
			require.NoError(t, err)
			require.Equal(t, all, got, n)
		}
	}
}

func TestDBResetRefusesDemotingLastSuperAdmin(t *testing.T) {
	r, uuid := permRig(t, nil)
	t.Setenv("USER", "operator")
	full := users.EnvAccess{User: true, Query: true, Carve: true, Admin: true}
	require.NoError(t, r.Users.ChangeAccess("admin", uuid, full))
	for _, cmd := range []string{"reset-permissions", "change-permissions"} {
		_, err := r.RunDB("user", cmd, "-u", "admin", "-e", "dev", "-U")
		if cmd == "change-permissions" {
			require.NoError(t, err) // additive never demotes
			continue
		}
		require.ErrorContains(t, err, "refusing to demote the last super-admin")
	}
	got, err := r.Users.GetEnvAccess("admin", uuid)
	require.NoError(t, err)
	require.Equal(t, full, got)
	// With a second super-admin the demotion is allowed.
	r.SeedUser("root", true)
	_, err = r.RunDB("user", "reset-permissions", "-u", "admin", "-e", "dev", "-U")
	require.NoError(t, err)
}

func TestDBResetRefusesSelfDemotion(t *testing.T) {
	r, uuid := permRig(t, nil)
	r.SeedUser("root", true) // not the last super-admin
	full := users.EnvAccess{User: true, Query: true, Carve: true, Admin: true}
	require.NoError(t, r.Users.ChangeAccess("admin", uuid, full))
	t.Setenv("USER", "admin")
	_, err := r.RunDB("user", "reset-permissions", "-u", "admin", "-e", "dev", "-U")
	require.ErrorContains(t, err, "self-demote")
	got, gerr := r.Users.GetEnvAccess("admin", uuid)
	require.NoError(t, gerr)
	require.Equal(t, full, got)
	// Same refusal and unchanged state through the API server (token user admin).
	_, err = r.RunAPI("user", "reset-permissions", "-u", "admin", "-e", "dev", "-U")
	require.ErrorContains(t, err, "self-demote")
	require.ErrorContains(t, err, "403")
	got, gerr = r.Users.GetEnvAccess("admin", uuid)
	require.NoError(t, gerr)
	require.Equal(t, full, got)
}

func TestAPIPermissionsForbiddenShown(t *testing.T) {
	r, uuid := permRig(t, map[string]users.EnvAccess{"bob": {User: true}})
	token := r.SeedUser("nobody", false)
	_, err := r.RunAPIAs(token, "user", "reset-permissions", "-u", "bob", "-e", "dev", "-a")
	require.ErrorContains(t, err, "403")
	_, err = r.RunAPIAs(token, "user", "show-permissions", "-u", "bob", "-e", "dev")
	require.ErrorContains(t, err, "403")
	got, gerr := r.Users.GetEnvAccess("bob", uuid)
	require.NoError(t, gerr)
	require.Equal(t, users.EnvAccess{User: true}, got)
}

func TestDBChangeNeverRefusedAndNonSuperAdminSelfResetAllowed(t *testing.T) {
	r, uuid := permRig(t, map[string]users.EnvAccess{"bob": {User: true}})
	// The sole super-admin (no env-admin row) and the shell user itself may add access.
	t.Setenv("USER", "admin")
	_, err := r.RunDB("user", "change-permissions", "-u", "admin", "-e", "dev", "-q")
	require.NoError(t, err)
	got, err := r.Users.GetEnvAccess("admin", uuid)
	require.NoError(t, err)
	require.True(t, got.Query)
	// A non-super-admin resetting themselves is not a lockout.
	t.Setenv("USER", "bob")
	_, err = r.RunDB("user", "change-permissions", "-u", "bob", "-e", "dev", "-c")
	require.NoError(t, err)
	_, err = r.RunDB("user", "reset-permissions", "-u", "bob", "-e", "dev", "-U")
	require.NoError(t, err)
	got, err = r.Users.GetEnvAccess("bob", uuid)
	require.NoError(t, err)
	require.Equal(t, users.EnvAccess{User: true}, got)
}

func TestAPIBulkPermissionsSelfDemoteRefused(t *testing.T) {
	r, uuid := permRig(t, nil)
	require.NoError(t, r.Users.ChangeAccess("admin", uuid, users.EnvAccess{User: true, Admin: true}))
	req, err := http.NewRequest(http.MethodPost, r.URL+"/api/v1/users/admin/permissions/all", strings.NewReader(`{"access":{"user":true}}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+r.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Contains(t, string(body), "super-admins cannot self-demote via this endpoint")
	got, err := r.Users.GetEnvAccess("admin", uuid)
	require.NoError(t, err)
	require.True(t, got.Admin)
}

// An actor holding only a legacy admin permission row with environment "" (no
// global admin flag) is not a global admin: both endpoints refuse it at the
// AdminLevel/NoEnvironment gate, before the self-demotion check.
func TestAPISelfDemoteRefusedForNonGlobalAdminActor(t *testing.T) {
	r, uuid := permRig(t, nil)
	token := r.SeedUser("envadmin", false)
	require.NoError(t, r.Users.CreatePermission(users.UserPermission{Username: "envadmin", Environment: "", AccessType: int(users.AdminLevel), AccessValue: true}))
	require.NoError(t, r.Users.ChangeAccess("envadmin", uuid, users.EnvAccess{User: true, Query: true}))
	for _, path := range []string{"permissions", "permissions/all"} {
		body := `{"env_uuid":"` + uuid + `","access":{"user":true}}`
		req, err := http.NewRequest(http.MethodPost, r.URL+"/api/v1/users/envadmin/"+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusForbidden, resp.StatusCode, path+" "+string(b))
		require.Contains(t, string(b), "no access", path)
	}
	got, err := r.Users.GetEnvAccess("envadmin", uuid)
	require.NoError(t, err)
	require.Equal(t, users.EnvAccess{User: true, Query: true}, got)
}
