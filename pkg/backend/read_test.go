package backend

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func primaryConfig() config.YAMLConfigurationDB {
	return config.YAMLConfigurationDB{
		Type: DBTypePostgres, Host: "primary", Port: 5432, Name: "osctrl",
		Username: "app", Password: "secret", SSLMode: "require",
		MaxIdleConns: 20, MaxOpenConns: 100, ConnMaxLifetime: 30,
	}
}

func TestReadReplicaConfigInheritsEmptyFields(t *testing.T) {
	p := primaryConfig()
	p.Read = config.YAMLConfigurationDBRead{Enabled: true, Host: "replica"}
	r, err := ReadReplicaConfig(p)
	require.NoError(t, err)
	assert.Equal(t, "replica", r.Host)
	assert.Equal(t, 5432, r.Port)
	assert.Equal(t, "app", r.Username)
	assert.Equal(t, "secret", r.Password)
	assert.Equal(t, "require", r.SSLMode)
	assert.Equal(t, 20, r.MaxIdleConns)
	assert.Equal(t, 100, r.MaxOpenConns)
	assert.Equal(t, "osctrl", r.Name)
	assert.Equal(t, 30, r.ConnMaxLifetime)
	assert.False(t, r.Read.Enabled, "the derived config must not itself ask for a replica")
}

func TestReadReplicaConfigOverrides(t *testing.T) {
	p := primaryConfig()
	p.Read = config.YAMLConfigurationDBRead{
		Enabled: true, Host: "replica", Port: 6432, Username: "ro", Password: "ro-secret",
		SSLMode: "verify-full", MaxIdleConns: 5, MaxOpenConns: 50,
	}
	r, err := ReadReplicaConfig(p)
	require.NoError(t, err)
	assert.Equal(t, 6432, r.Port)
	assert.Equal(t, "ro", r.Username)
	assert.Equal(t, "ro-secret", r.Password)
	assert.Equal(t, "verify-full", r.SSLMode)
	assert.Equal(t, 5, r.MaxIdleConns)
	assert.Equal(t, 50, r.MaxOpenConns)
}

func TestReadReplicaConfigRejectsSQLite(t *testing.T) {
	p := config.YAMLConfigurationDB{Type: DBTypeSQLite, FilePath: "x.db",
		Read: config.YAMLConfigurationDBRead{Enabled: true}}
	_, err := ReadReplicaConfig(p)
	assert.Error(t, err)
}

// With the replica off, Read is the primary connection itself, so callers can
// use it unconditionally.
func TestCreateDBManagerReadDefaultsToPrimary(t *testing.T) {
	db, err := CreateDBManager(&config.YAMLConfigurationDB{Type: DBTypeSQLite, FilePath: t.TempDir() + "/o.db"})
	require.NoError(t, err)
	assert.Same(t, db.Conn, db.Read)
	assert.NoError(t, db.Check())
}

func TestCreateDBManagerRefusesUnreachableReplica(t *testing.T) {
	_, err := CreateDBManager(&config.YAMLConfigurationDB{Type: DBTypeSQLite, FilePath: t.TempDir() + "/o.db",
		Read: config.YAMLConfigurationDBRead{Enabled: true}})
	assert.Error(t, err)
}
