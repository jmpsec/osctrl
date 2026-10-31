package nodeconfig

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func replicaFlagsManager(t *testing.T) *FlagsManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := newFlagsManagerWithStore(db, newFakeStore())
	require.NoError(t, err)
	return m
}

// Replica() reads from ReadDB, without the cache, while the manager itself
// keeps the primary.
func TestFlagsManagerReplicaReadsReadDB(t *testing.T) {
	primary, replica := replicaFlagsManager(t), replicaFlagsManager(t)
	_, err := replica.RecordReport("down", 7, types.OsctrldStatusRequest{}, reportAt)
	require.NoError(t, err)
	primary.ReadDB = replica.db

	got, err := primary.Replica().CountDown(reportAt)
	require.NoError(t, err)
	assert.Equal(t, map[uint]int{7: 1}, got)
	assert.Nil(t, primary.Replica().cache)

	got, err = primary.CountDown(reportAt)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestFlagsManagerReplicaWithoutReadDBIsSelf(t *testing.T) {
	m := replicaFlagsManager(t)
	assert.Same(t, m, m.Replica())
}
