package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// bothModes runs fn once per mode with the matching rig runner.
func bothModes(t *testing.T, rig *parityRig, fn func(t *testing.T, run func(...string) (string, error))) {
	t.Helper()
	for mode, run := range map[string]func(...string) (string, error){"db": rig.RunDB, "api": rig.RunAPI} {
		t.Run(mode, func(t *testing.T) { fn(t, run) })
	}
}

func TestCarveActionsUseCarveEndpoints(t *testing.T) {
	rig := newParityRig(t)
	env, err := rig.Envs.Get("dev")
	require.NoError(t, err)
	qm := queries.CreateQueries(rig.DB)
	bothModes(t, rig, func(t *testing.T, run func(...string) (string, error)) {
		for _, action := range []string{"complete", "expire", "delete"} {
			name := "carve-" + run0(t) + action
			require.NoError(t, qm.Create(&queries.DistributedQuery{Name: name, Type: queries.CarveQueryType, EnvironmentID: env.ID, Active: true, Expiration: time.Now().Add(time.Hour)}))
			_, err := run("carve", action, "-n", name, "-e", "dev")
			require.NoError(t, err, action)
			q, err := qm.Get(name, env.ID)
			require.NoError(t, err)
			// Delete is a soft delete: the row stays, flagged.
			require.True(t, map[string]bool{"complete": q.Completed, "expire": q.Expired, "delete": q.Deleted}[action], action)
			var n int64
			rig.DB.Model(&auditlog.AuditLog{}).Where("log_type = ? AND line LIKE ?", auditlog.LogTypeCarve, "%"+action+" carve "+name).Count(&n)
			require.EqualValues(t, 1, n, "carve audit action for %s", action)
		}
	})
}

func TestRotateRotatesSecretPaths(t *testing.T) {
	rig := newParityRig(t)
	bothModes(t, rig, func(t *testing.T, run func(...string) (string, error)) {
		for _, target := range []string{"enroll", "remove"} {
			before, err := rig.Envs.Get("dev")
			require.NoError(t, err)
			_, err = run("env", "node-actions", "rotate-"+target, "--name", "dev")
			require.NoError(t, err)
			after, err := rig.Envs.Get("dev")
			require.NoError(t, err)
			if target == "enroll" {
				require.NotEqual(t, before.EnrollSecretPath, after.EnrollSecretPath)
				require.Equal(t, before.RemoveSecretPath, after.RemoveSecretPath)
			} else {
				require.NotEqual(t, before.RemoveSecretPath, after.RemoveSecretPath)
				require.Equal(t, before.EnrollSecretPath, after.EnrollSecretPath)
			}
		}
	})
}

func TestUserDeleteRemovesPermissionsAndUser(t *testing.T) {
	rig := newParityRig(t)
	env, err := rig.Envs.Get("dev")
	require.NoError(t, err)
	bothModes(t, rig, func(t *testing.T, run func(...string) (string, error)) {
		name := "victim-" + run0(t)
		rig.SeedUser(name, false)
		require.NoError(t, rig.Users.SetEnvLevel(name, env.UUID, users.UserLevel, true))
		require.NoError(t, rig.DB.AutoMigrate(&mfa.TOTPEnrollment{}, &mfa.RecoveryCode{}, &mfa.Credential{}, &mfa.Challenge{}))
		require.NoError(t, rig.DB.Create(&mfa.TOTPEnrollment{Username: name, Secret: "S", Confirmed: true}).Error)
		_, err := run("user", "delete", "-u", name)
		require.NoError(t, err)
		require.False(t, rig.Users.Exists(name))
		var n int64
		rig.DB.Model(&users.UserPermission{}).Where("username = ?", name).Count(&n)
		require.Zero(t, n, "orphaned permissions")
		rig.DB.Model(&mfa.TOTPEnrollment{}).Where("username = ?", name).Count(&n)
		require.Zero(t, n, "orphaned MFA enrollment")
	})
}

// run0 is a path-safe unique suffix from the subtest name.
func run0(t *testing.T) string { return strings.NewReplacer("/", "-", "_", "-").Replace(t.Name()) }

func TestSuccessMessages(t *testing.T) {
	rig := newParityRig(t)
	require.NoError(t, settings.NewSettings(rig.DB).NewStringValue("tls", "parity-setting", "a", settings.NoEnvironmentID))
	require.NoError(t, rig.Envs.AddQueryPackConf("dev", "p1", environments.PackEntry{Platform: "linux"}))
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"settings", "update", "-n", "parity-setting", "-s", "tls", "-t", "string", "--string", "b"}, "setting updated successfully"},
		{[]string{"env", "remove-pack", "-n", "dev", "-p", "p1"}, "pack p1 was removed successfully"},
		{[]string{"env", "remove-osquery-option", "-n", "dev", "-o", "nope"}, "option nope was removed successfully"},
	} {
		out, err := rig.RunDB(tc.args...)
		require.NoError(t, err, tc.args)
		require.Contains(t, out, tc.want)
	}
}

// Pins the "{}" body: the server decodes JSON for every enroll/remove action.
func TestEnvEnrollRemoveActionsOverAPI(t *testing.T) {
	rig := newParityRig(t)
	for _, target := range []string{"enroll", "remove"} {
		for _, action := range []string{"extend", "expire", "notexpire"} {
			_, err := rig.RunAPI("env", "node-actions", action+"-"+target, "--name", "dev")
			require.NoError(t, err, action+"-"+target)
		}
	}
}

func TestSettingUpdateReportsFailureAndInfo(t *testing.T) {
	rig := newParityRig(t)
	_, err := rig.RunDB("settings", "update", "-n", "missing", "-s", "tls", "-t", "string", "--string", "b", "--info", "i")
	require.ErrorContains(t, err, "error set type")
	require.NoError(t, settings.NewSettings(rig.DB).NewStringValue("tls", "has-info", "a", settings.NoEnvironmentID))
	_, err = rig.RunDB("settings", "update", "-n", "has-info", "-s", "tls", "-t", "string", "--string", "b", "--info", "i")
	require.NoError(t, err)
}
