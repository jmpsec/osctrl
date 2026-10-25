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
