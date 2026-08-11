package environments

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPackagesTestDB(t *testing.T) *EnvManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&TLSEnvironment{}, &EnvironmentPackage{}))
	return &EnvManager{DB: db}
}

func TestAddPackage_Success(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery-amd64.deb", true))
	require.NoError(t, mgr.AddPackage(env.ID, "deb", "arm64", "osquery-arm64.deb", false))

	pkgs, err := mgr.GetPackagesByType(env.ID, "deb")
	require.NoError(t, err)
	assert.Len(t, pkgs, 2)
	assert.Equal(t, "amd64", pkgs[0].Architecture)
	assert.Equal(t, "arm64", pkgs[1].Architecture)
}

func TestAddPackage_InvalidArchitecture(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	err := mgr.AddPackage(env.ID, "deb", "bogus-arch", "url", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid architecture")
}

func TestGetPackage_ByArchitecture(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery-amd64.deb", false))
	require.NoError(t, mgr.AddPackage(env.ID, "deb", "arm64", "osquery-arm64.deb", false))

	pkg, err := mgr.GetPackage(env.ID, "deb", "arm64")
	require.NoError(t, err)
	assert.Equal(t, "osquery-arm64.deb", pkg.URL)
	assert.Equal(t, "arm64", pkg.Architecture)
}

func TestGetPackage_FallbackToDefault(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery-amd64.deb", true))
	require.NoError(t, mgr.AddPackage(env.ID, "deb", "arm64", "osquery-arm64.deb", false))

	// Request an arch that doesn't exist — should fall back to default.
	pkg, err := mgr.GetPackage(env.ID, "deb", "x86_64")
	require.NoError(t, err)
	assert.Equal(t, "osquery-amd64.deb", pkg.URL)
	assert.True(t, pkg.IsDefault)
}

func TestGetPackage_FallbackToFirstAvailable(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery-amd64.deb", false))
	require.NoError(t, mgr.AddPackage(env.ID, "deb", "arm64", "osquery-arm64.deb", false))

	// No default set, no exact match — falls back to first by architecture order.
	pkg, err := mgr.GetPackage(env.ID, "deb", "x86_64")
	require.NoError(t, err)
	assert.Equal(t, "amd64", pkg.Architecture)
}

func TestRemovePackage_Success(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery.deb", false))
	pkgs, _ := mgr.GetPackagesByType(env.ID, "deb")
	require.Len(t, pkgs, 1)

	require.NoError(t, mgr.RemovePackage(env.ID, pkgs[0].ID))
	pkgs, _ = mgr.GetPackagesByType(env.ID, "deb")
	assert.Empty(t, pkgs)
}

func TestRemovePackage_NotFound(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	err := mgr.RemovePackage(env.ID, 999)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestSetDefaultPackage(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret"}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.AddPackage(env.ID, "deb", "amd64", "osquery-amd64.deb", true))
	require.NoError(t, mgr.AddPackage(env.ID, "deb", "arm64", "osquery-arm64.deb", false))

	pkgs, _ := mgr.GetPackagesByType(env.ID, "deb")
	assert.True(t, pkgs[0].IsDefault)
	assert.False(t, pkgs[1].IsDefault)

	// Set arm64 as default.
	require.NoError(t, mgr.SetDefaultPackage(env.ID, pkgs[1].ID))

	pkgs, _ = mgr.GetPackagesByType(env.ID, "deb")
	assert.False(t, pkgs[0].IsDefault)
	assert.True(t, pkgs[1].IsDefault)
}

func TestMigrateLegacyPackages(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{
		Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret",
		DebPackage: "osquery.deb",
		RpmPackage: "https://example.com/osquery.rpm",
	}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.MigrateLegacyPackages())

	// DEB should be migrated.
	debPkgs, err := mgr.GetPackagesByType(env.ID, "deb")
	require.NoError(t, err)
	assert.Len(t, debPkgs, 1)
	assert.Equal(t, "osquery.deb", debPkgs[0].URL)
	assert.True(t, debPkgs[0].IsDefault)

	// RPM should be migrated.
	rpmPkgs, err := mgr.GetPackagesByType(env.ID, "rpm")
	require.NoError(t, err)
	assert.Len(t, rpmPkgs, 1)
	assert.Equal(t, "https://example.com/osquery.rpm", rpmPkgs[0].URL)

	// MSI and PKG should not exist (were empty).
	msiPkgs, _ := mgr.GetPackagesByType(env.ID, "msi")
	assert.Empty(t, msiPkgs)
}

func TestMigrateLegacyPackages_Idempotent(t *testing.T) {
	mgr := setupPackagesTestDB(t)
	env := TLSEnvironment{
		Name: "test", UUID: "test-uuid", Hostname: "host", Secret: "secret",
		DebPackage: "osquery.deb",
	}
	require.NoError(t, mgr.Create(&env))

	require.NoError(t, mgr.MigrateLegacyPackages())
	require.NoError(t, mgr.MigrateLegacyPackages())

	debPkgs, _ := mgr.GetPackagesByType(env.ID, "deb")
	assert.Len(t, debPkgs, 1, "migration should not duplicate")
}
