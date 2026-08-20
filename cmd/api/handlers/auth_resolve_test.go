package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/auth"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupResolveTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&users.AdminUser{}))
	return db
}

func TestJITCreatesAdminWhenNoAdminsExist(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-1",
		PreferredUsername: "first-user",
		Email:             "first@example.com",
		Name:              "First User",
	}

	user, err := h.resolveFederatedUser(identity, true, "oidc")
	require.NoError(t, err)
	require.True(t, user.Admin, "first JIT user should be admin when no admins exist")
	require.False(t, user.Service)
	require.Equal(t, "oidc", user.AuthSource)
}

func TestJITCreatesNonAdminWhenAdminsExist(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	// Pre-create an admin user.
	existing, err := userMgr.New("existing-admin", "password", "", "", true, false)
	require.NoError(t, err)
	require.NoError(t, userMgr.Create(existing))

	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-2",
		PreferredUsername: "new-user",
		Email:             "new@example.com",
		Name:              "New User",
	}

	user, err := h.resolveFederatedUser(identity, true, "oidc")
	require.NoError(t, err)
	require.False(t, user.Admin, "JIT user should NOT be admin when admins already exist")
	require.False(t, user.Service)
}

func TestJITRejectedWhenDisabled(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-3",
		PreferredUsername: "rejected-user",
	}

	_, err := h.resolveFederatedUser(identity, false, "oidc")
	require.Error(t, err)
}

func TestJITReturnsExistingUserByName(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	// Pre-create a federated user (non-admin, with auth_source).
	existing, err := userMgr.New("fed-user", "", "fed@example.com", "Fed User", false, false)
	require.NoError(t, err)
	existing.AuthSource = "oidc"
	require.NoError(t, userMgr.Create(existing))

	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-4",
		PreferredUsername: "fed-user",
	}

	user, err := h.resolveFederatedUser(identity, true, "oidc")
	require.NoError(t, err)
	require.Equal(t, "fed-user", user.Username)
	require.False(t, user.Admin, "existing non-admin user should stay non-admin")
}

func TestJITRejectsLocalAccountClaim(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	// Pre-create a local (password) user with no AuthSource.
	local, err := userMgr.New("local-user", "password", "", "", false, false)
	require.NoError(t, err)
	require.NoError(t, userMgr.Create(local))

	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-5",
		PreferredUsername: "local-user",
	}

	_, err = h.resolveFederatedUser(identity, true, "oidc")
	require.Error(t, err)
}
