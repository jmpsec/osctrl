package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ptr(b bool) *bool { return &b }

func roleTestManager(t *testing.T) *UserManager {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return CreateUserManager(db)
}

func TestHasRole(t *testing.T) {
	all := []GlobalRole{RoleSuperuser, RoleUserManagement, RoleEnvManagement, RoleReadOnly, RoleAlertAdmin}
	tests := []struct {
		name string
		user AdminUser
		want map[GlobalRole]bool
	}{
		{"superuser", AdminUser{Admin: true}, map[GlobalRole]bool{RoleSuperuser: true, RoleUserManagement: true, RoleEnvManagement: true, RoleReadOnly: true, RoleAlertAdmin: true}},
		{"user admin", AdminUser{UserAdmin: true}, map[GlobalRole]bool{RoleUserManagement: true, RoleReadOnly: true}},
		{"env manager", AdminUser{EnvManager: true}, map[GlobalRole]bool{RoleEnvManagement: true, RoleReadOnly: true}},
		{"read only", AdminUser{ReadOnlyAdmin: true}, map[GlobalRole]bool{RoleReadOnly: true}},
		{"alert admin", AdminUser{AlertAdmin: true}, map[GlobalRole]bool{RoleAlertAdmin: true}},
		{"zero", AdminUser{}, map[GlobalRole]bool{}},
	}
	for _, tt := range tests {
		for _, r := range all {
			require.Equal(t, tt.want[r], tt.user.HasRole(r), "%s role %d", tt.name, r)
		}
	}
}

func TestHasRoleContext(t *testing.T) {
	m := roleTestManager(t)
	require.NoError(t, m.Create(AdminUser{Username: "u", AlertAdmin: true}))
	for _, ctx := range []context.Context{WithPermissionCache(context.Background()), context.Background()} {
		require.True(t, m.HasRoleContext(ctx, "u", RoleAlertAdmin))
		require.False(t, m.HasRoleContext(ctx, "u", RoleReadOnly))
		require.False(t, m.HasRoleContext(ctx, "nobody", RoleAlertAdmin))
	}
}

func TestSetRoles(t *testing.T) {
	m := roleTestManager(t)
	require.NoError(t, m.Create(AdminUser{Username: "u"}))
	require.NoError(t, m.SetRoles("u", RoleSet{AlertAdmin: ptr(true)}))
	u, err := m.Get("u")
	require.NoError(t, err)
	require.True(t, u.AlertAdmin)
	require.False(t, u.UserAdmin || u.EnvManager || u.ReadOnlyAdmin)
	require.NoError(t, m.SetRoles("u", RoleSet{}))
	u, _ = m.Get("u")
	require.True(t, u.AlertAdmin)
	require.Error(t, m.SetRoles("ghost", RoleSet{AlertAdmin: ptr(true)}))
}

func TestCheckManageUser(t *testing.T) {
	m := roleTestManager(t)
	for _, u := range []AdminUser{
		{Username: "root", Admin: true},
		{Username: "ua", UserAdmin: true},
		{Username: "ro", ReadOnlyAdmin: true},
		{Username: "plain"},
		{Username: "root2", Admin: true},
	} {
		require.NoError(t, m.Create(u))
	}
	tests := []struct {
		name, actor, target string
		grant               bool
		want                error
	}{
		{"superuser grants", "root", "plain", true, nil},
		{"superuser on superuser", "root", "root2", true, nil},
		{"user admin on plain", "ua", "plain", false, nil},
		{"user admin on superuser", "ua", "root", false, ErrSuperuserTarget},
		{"user admin grants superuser", "ua", "plain", true, ErrSuperuserGrant},
		{"user admin on self", "ua", "ua", false, nil},
		{"no user management", "ro", "plain", false, ErrNoUserManagement},
		{"unknown actor", "ghost", "plain", false, ErrNoUserManagement},
		{"create flow", "ua", "new", false, nil},
		{"create flow grant by user admin", "ua", "new", true, ErrSuperuserGrant},
		{"create flow grant by superuser", "root", "new", true, nil},
	}
	for _, tt := range tests {
		err := m.CheckManageUser(WithPermissionCache(context.Background()), tt.actor, tt.target, tt.grant)
		if tt.want == nil {
			require.NoError(t, err, tt.name)
		} else {
			require.ErrorIs(t, err, tt.want, tt.name)
		}
	}
}

// A DB error on the target lookup must fail closed, not look like a create flow.
func TestCheckManageUserTargetLookupError(t *testing.T) {
	m := roleTestManager(t)
	actor := AdminUser{Username: "ua", UserAdmin: true}
	require.NoError(t, m.Create(actor))
	ctx := WithPermissionCache(context.Background())
	CacheAuthenticatedUser(ctx, actor)
	sqlDB, err := m.DB.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	err = m.CheckManageUser(ctx, "ua", "root", false)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSuperuserTarget)
	require.Error(t, m.SetRoles("ua", RoleSet{AlertAdmin: ptr(true)}))
}
