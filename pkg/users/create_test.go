package users

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// failPermissionInserts makes every user_permissions INSERT on db fail until
// the test:fail_perms callback is removed.
func failPermissionInserts(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:fail_perms", func(tx *gorm.DB) {
		if tx.Statement.Table == "user_permissions" {
			_ = tx.AddError(errors.New("injected permission failure"))
		}
	}))
}

func TestCreateWithPermissionsIsAtomic(t *testing.T) {
	m := lockoutManager(t, nil, nil)
	u, err := m.New("carol", "", "", "", false, false)
	require.NoError(t, err)
	perms := m.GenPermissions("carol", "root", m.GenEnvUserAccess([]string{"env-a", "env-b"}, true, true, false, false))

	failPermissionInserts(t, m.DB)
	require.ErrorContains(t, m.CreateWithPermissions(u, perms), "injected permission failure")
	require.False(t, m.Exists("carol"), "no half-created user")
	var n int64
	require.NoError(t, m.DB.Model(&UserPermission{}).Where("username = ?", "carol").Count(&n).Error)
	require.Zero(t, n)

	require.NoError(t, m.DB.Callback().Create().Remove("test:fail_perms"))
	require.NoError(t, m.CreateWithPermissions(u, perms), "a retry succeeds")
	require.True(t, m.Exists("carol"))
	access, err := m.GetAccess("carol")
	require.NoError(t, err)
	require.Equal(t, UserAccess{"env-a": {User: true, Query: true}, "env-b": {User: true, Query: true}}, access)
}

func TestPermissionWritesRefuseBlankEnvironment(t *testing.T) {
	m := lockoutManager(t, nil, []string{"bob"})
	require.Error(t, m.CreatePermission(UserPermission{Username: "bob", AccessType: int(AdminLevel), AccessValue: true}))
	require.Error(t, m.SetEnvLevel("bob", NoEnvironment, AdminLevel, true))
	u, err := m.New("carol", "", "", "", false, false)
	require.NoError(t, err)
	require.Error(t, m.CreateWithPermissions(u, []UserPermission{{Username: "carol", AccessType: int(AdminLevel), AccessValue: true}}))
	require.False(t, m.Exists("carol"))
	var n int64
	require.NoError(t, m.DB.Model(&UserPermission{}).Where("environment = ?", "").Count(&n).Error)
	require.Zero(t, n)
	require.NoError(t, m.SetEnvLevel("bob", "env-a", UserLevel, true))
}
