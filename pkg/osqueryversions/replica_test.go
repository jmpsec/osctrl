package osqueryversions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func replicaTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	require.NoError(t, err)
	m, err := NewManager(db)
	require.NoError(t, err)
	return m
}

func TestManagerReplicaReadsReadDB(t *testing.T) {
	primary, replica := replicaTestManager(t), replicaTestManager(t)
	require.NoError(t, replica.db.Create(&Rollout{EnvironmentID: 9, RequestID: "r", Version: "5.13.0", State: RolloutPaused, Thresholds: "[]"}).Error)
	primary.ReadDB = replica.db

	got, err := primary.Replica().CountPaused()
	require.NoError(t, err)
	assert.Equal(t, map[uint]int{9: 1}, got)

	got, err = primary.CountPaused()
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestManagerReplicaWithoutReadDBIsSelf(t *testing.T) {
	m := replicaTestManager(t)
	assert.Same(t, m, m.Replica())
}
