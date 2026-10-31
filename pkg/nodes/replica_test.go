package nodes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func memDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	return db
}

// Replica() must read from ReadDB, and only the copy it returns: the manager
// itself keeps reading the primary.
func TestReplicaReadsFromReadDB(t *testing.T) {
	primary, replica := memDB(t), memDB(t)
	require.NoError(t, primary.Create(&OsqueryNode{UUID: "P", Environment: "dev"}).Error)
	require.NoError(t, replica.Create(&OsqueryNode{UUID: "R", Environment: "dev"}).Error)
	n := &NodeManager{DB: primary, ReadDB: replica, Cache: &NodeCache{}}

	got, err := n.Replica().GetByEnv("dev", AllNodes, 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "R", got[0].UUID)
	assert.Nil(t, n.Replica().Cache, "replica reads must not populate the node cache")

	got, err = n.GetByEnv("dev", AllNodes, 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "P", got[0].UUID)
}

func TestReplicaWithoutReadDBIsThePrimary(t *testing.T) {
	n := &NodeManager{DB: memDB(t)}
	assert.Same(t, n, n.Replica())
}
