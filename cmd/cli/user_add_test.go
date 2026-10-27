package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gorm.io/gorm"
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

// DB-mode `user add`: a permission-row failure leaves no half-created user,
// and a retry succeeds.
func TestUserAddDBPermissionFailureCreatesNothing(t *testing.T) {
	r := newParityRig(t)
	audit, err := auditlog.CreateAuditLogManager(r.DB, "osctrl-cli", true)
	require.NoError(t, err)
	adminUsers, envs, auditlogsmgr, dbFlag, silentFlag = r.Users, r.Envs, audit, true, true // restored by the rig
	add := &cli.Command{
		Name: "add",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username"}, &cli.StringFlag{Name: "password"},
			&cli.StringFlag{Name: "email"}, &cli.StringFlag{Name: "fullname"},
			&cli.BoolFlag{Name: "admin"}, &cli.BoolFlag{Name: "service"},
			&cli.StringFlag{Name: "environment"},
		},
		Action: addUser,
	}
	require.NoError(t, r.DB.Callback().Create().Before("gorm:create").Register("test:fail_perms", func(tx *gorm.DB) {
		if tx.Statement.Table == "user_permissions" {
			_ = tx.AddError(errors.New("injected permission failure"))
		}
	}))
	err = add.Run(context.Background(), []string{"add", "--username", "carol", "--environment", "dev"})
	require.ErrorContains(t, err, "injected permission failure")
	require.False(t, r.Users.Exists("carol"))
	var n int64
	require.NoError(t, r.DB.Model(&users.UserPermission{}).Where("username = ?", "carol").Count(&n).Error)
	require.Zero(t, n)
	require.NoError(t, r.DB.Callback().Create().Remove("test:fail_perms"))
	require.NoError(t, add.Run(context.Background(), []string{"add", "--username", "carol", "--environment", "dev"}))
	require.Len(t, userPerms(t, r, "carol"), 4)
}
