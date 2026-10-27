package main

import (
	"context"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// editUserCommand builds a command with the flags editUser reads.
func editUserCommand() *cli.Command {
	return &cli.Command{
		Name: "edit",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username"},
			&cli.StringFlag{Name: "password"},
			&cli.StringFlag{Name: "email"},
			&cli.StringFlag{Name: "fullname"},
			&cli.BoolFlag{Name: "admin"},
			&cli.BoolFlag{Name: "non-admin"},
			&cli.BoolFlag{Name: "service"},
			&cli.BoolFlag{Name: "non-service"},
		},
		Action: editUser,
	}
}

// With --db the API client is never initialised, and apiFlag defaults to true:
// editing a user must use the database only and must not touch the API client.
func TestEditUserWithDBDoesNotUseAPIClient(t *testing.T) {
	oldUsers, oldAudit, oldDB, oldAPI, oldAPIClient, oldSilent := adminUsers, auditlogsmgr, dbFlag, apiFlag, osctrlAPI, silentFlag
	t.Cleanup(func() {
		adminUsers, auditlogsmgr, dbFlag, apiFlag, osctrlAPI, silentFlag = oldUsers, oldAudit, oldDB, oldAPI, oldAPIClient, oldSilent
	})
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	adminUsers = users.CreateUserManager(db)
	auditlogsmgr, err = auditlog.CreateAuditLogManager(db, "osctrl-cli", true)
	require.NoError(t, err)
	dbFlag, apiFlag, silentFlag = true, true, true
	osctrlAPI = nil

	u, err := adminUsers.New("admin", "old-password", "a@example.com", "Admin", true, false)
	require.NoError(t, err)
	require.NoError(t, adminUsers.Create(u))

	require.NotPanics(t, func() {
		require.NoError(t, editUserCommand().Run(context.Background(), []string{"edit", "--username", "admin", "--password", "new-password"}))
	})

	ok, _ := adminUsers.CheckLoginCredentials("admin", "new-password")
	require.True(t, ok, "the new password must work")
	ok, _ = adminUsers.CheckLoginCredentials("admin", "old-password")
	require.False(t, ok, "the old password must stop working")
}

// `user edit --non-admin` and the shell DB store apply users.CheckLockout:
// never the last super-admin, never yourself; the API refuses self-demotion (403).
func TestUserEditDemotionLockout(t *testing.T) {
	r := newParityRig(t)
	t.Setenv("USER", "operator")
	_, err := r.RunDB("user", "edit", "-u", "admin", "--non-admin")
	require.ErrorContains(t, err, "refusing to demote the last super-admin")
	adminUsers = r.Users // restored by the rig
	require.ErrorContains(t, (&dbStore{}).EditUserField("admin", "admin", "false"), "refusing to demote the last super-admin")
	require.True(t, r.Users.IsAdmin("admin"))

	r.SeedUser("root", true)
	t.Setenv("USER", "admin")
	_, err = r.RunDB("user", "edit", "-u", "admin", "--non-admin", "--email", "x@example.com")
	require.ErrorContains(t, err, "self-demote")
	require.ErrorContains(t, (&dbStore{}).EditUserField("admin", "admin", "false"), "self-demote")
	_, err = r.RunAPI("user", "edit", "-u", "admin", "--non-admin")
	require.ErrorContains(t, err, "403")
	u, err := r.Users.Get("admin")
	require.NoError(t, err)
	require.True(t, u.Admin)
	require.Empty(t, u.Email, "nothing is written when the demotion is refused")

	// Demoting another admin while one remains, and promotion, are unaffected.
	_, err = r.RunDB("user", "edit", "-u", "root", "--non-admin")
	require.NoError(t, err)
	require.False(t, r.Users.IsAdmin("root"))
	require.NoError(t, (&dbStore{}).EditUserField("root", "admin", "true"))
	require.NoError(t, (&dbStore{}).EditUserField("root", "admin", "false"))
	require.False(t, r.Users.IsAdmin("root"))
	_, err = r.RunAPI("user", "edit", "-u", "root", "--admin")
	require.NoError(t, err)
	_, err = r.RunAPI("user", "edit", "-u", "root", "--non-admin")
	require.NoError(t, err)
	require.False(t, r.Users.IsAdmin("root"))
}

// DB-mode `user delete` (and the shell DB store) never deletes the last
// super-admin or the shell user's own super-admin account.
func TestUserDeleteLockout(t *testing.T) {
	r := newParityRig(t)
	t.Setenv("USER", "operator")
	_, err := r.RunDB("user", "delete", "-u", "admin")
	require.ErrorContains(t, err, "refusing to demote the last super-admin")
	adminUsers = r.Users // restored by the rig
	require.ErrorContains(t, (&dbStore{}).DeleteUser("admin"), "refusing to demote the last super-admin")
	r.SeedUser("root", true)
	t.Setenv("USER", "admin")
	_, err = r.RunDB("user", "delete", "-u", "admin")
	require.ErrorContains(t, err, "self-demote")
	require.True(t, r.Users.IsAdmin("admin"))
	_, err = r.RunDB("user", "delete", "-u", "root")
	require.NoError(t, err)
	require.False(t, r.Users.Exists("root"))
}

// The API-mode shell store must actually demote/undemote (the API only acts on
// not_admin / not_service), and keep the lockout refusals.
func TestAPIStoreEditUserFieldDemotes(t *testing.T) {
	r := newParityRig(t)
	t.Setenv("USER", "operator")
	s := &apiStore{api: r.API}
	r.SeedUser("root", true)

	require.NoError(t, s.EditUserField("root", "admin", "false"))
	require.False(t, r.Users.IsAdmin("root"))
	require.NoError(t, s.EditUserField("root", "admin", "true"))
	require.True(t, r.Users.IsAdmin("root"))

	require.NoError(t, s.EditUserField("root", "service", "true"))
	u, err := r.Users.Get("root")
	require.NoError(t, err)
	require.True(t, u.Service)
	require.NoError(t, s.EditUserField("root", "service", "false"))
	u, err = r.Users.Get("root")
	require.NoError(t, err)
	require.False(t, u.Service)

	// self-demotion refused (token user is "admin")
	require.Error(t, s.EditUserField("admin", "admin", "false"))
	require.True(t, r.Users.IsAdmin("admin"))
	// last super-admin refused: demote root, then admin is the last one
	require.NoError(t, s.EditUserField("root", "admin", "false"))
	require.Error(t, s.EditUserField("admin", "admin", "false"))
	require.True(t, r.Users.IsAdmin("admin"))
}
