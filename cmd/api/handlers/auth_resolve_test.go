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

	user, err := h.resolveFederatedUser(identity, federatedPolicy{authSource: "oidc", jitProvision: true}, "10.0.0.1")
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

	user, err := h.resolveFederatedUser(identity, federatedPolicy{authSource: "oidc", jitProvision: true}, "10.0.0.1")
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

	_, err := h.resolveFederatedUser(identity, federatedPolicy{authSource: "oidc", jitProvision: false}, "10.0.0.1")
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

	user, err := h.resolveFederatedUser(identity, federatedPolicy{authSource: "oidc", jitProvision: true}, "10.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "fed-user", user.Username)
	require.False(t, user.Admin, "existing non-admin user should stay non-admin")
}

// Without linkLocalAccounts a federated identity must not inherit a local
// password account of the same name — otherwise anyone who can make the IdP
// assert "admin" would land in the local admin's row.
func TestFederatedLoginRejectsLocalAccountByDefault(t *testing.T) {
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

	_, err = h.resolveFederatedUser(identity, federatedPolicy{authSource: "oidc", jitProvision: true}, "10.0.0.1")
	require.Error(t, err)

	// The rejection must leave the account exactly as it was — in
	// particular it must not have been stamped as federated.
	after, err := userMgr.Get("local-user")
	require.NoError(t, err)
	require.Equal(t, "", after.AuthSource, "a rejected claim must not restamp the row")
}

// With linkLocalAccounts the operator has explicitly delegated that decision
// to the IdP, so the same login links instead of failing.
func TestFederatedLoginLinksLocalAccountWhenAllowed(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	local, err := userMgr.New("jane@corp.com", "password", "jane@corp.com", "Jane", false, false)
	require.NoError(t, err)
	require.NoError(t, userMgr.Create(local))

	h := &HandlersApi{Users: userMgr}

	identity := auth.ResolvedIdentity{
		Subject:           "sub-6",
		PreferredUsername: "jane@corp.com",
	}

	user, err := h.resolveFederatedUser(identity,
		federatedPolicy{authSource: "oidc", jitProvision: false, linkLocalAccounts: true}, "10.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "jane@corp.com", user.Username)
	require.Equal(t, "oidc", user.AuthSource, "linking stamps the row for the protocol that claimed it")

	// Persisted, not just returned — the next login takes the cheaper
	// already-federated path.
	stored, err := userMgr.Get("jane@corp.com")
	require.NoError(t, err)
	require.Equal(t, "oidc", stored.AuthSource)

	// Linking must not invent privileges.
	require.False(t, stored.Admin, "linking must not promote the account")
}

// Linking is a one-time transition: once stamped, the account resolves through
// the ordinary federated path even if the operator turns the flag back off.
func TestLinkedAccountResolvesAfterFlagIsDisabled(t *testing.T) {
	db := setupResolveTestDB(t)
	userMgr := users.CreateUserManager(db)
	local, err := userMgr.New("jane@corp.com", "password", "", "", false, false)
	require.NoError(t, err)
	require.NoError(t, userMgr.Create(local))

	h := &HandlersApi{Users: userMgr}
	identity := auth.ResolvedIdentity{Subject: "sub-7", PreferredUsername: "jane@corp.com"}

	_, err = h.resolveFederatedUser(identity,
		federatedPolicy{authSource: "oidc", linkLocalAccounts: true}, "10.0.0.1")
	require.NoError(t, err)

	user, err := h.resolveFederatedUser(identity,
		federatedPolicy{authSource: "oidc", linkLocalAccounts: false}, "10.0.0.1")
	require.NoError(t, err, "an already-linked account no longer needs the flag")
	require.Equal(t, "oidc", user.AuthSource)
}
