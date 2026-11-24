package queries

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPruneCompletedBeforeKeepsActiveQueries(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateQueries(db)

	now := time.Now()
	old := now.Add(-72 * time.Hour)
	oldQuery := DistributedQuery{Name: "old", Active: false, Completed: true, UpdatedAt: old, CreatedAt: old}
	recentQuery := DistributedQuery{Name: "recent", Active: false, Completed: true, UpdatedAt: now, CreatedAt: now}
	activeQuery := DistributedQuery{Name: "active", Active: true, Completed: true, UpdatedAt: old, CreatedAt: old}
	require.NoError(t, db.Create(&oldQuery).Error)
	require.NoError(t, db.Create(&recentQuery).Error)
	require.NoError(t, db.Create(&activeQuery).Error)
	require.NoError(t, db.Create(&NodeQuery{NodeID: 1, QueryID: oldQuery.ID}).Error)
	require.NoError(t, db.Create(&DistributedQueryTarget{Name: oldQuery.Name, Type: "uuid", Value: "node"}).Error)

	deleted, err := m.PruneCompletedBefore(now.Add(-24 * time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)

	var queriesCount, nodesCount, targetsCount int64
	require.NoError(t, db.Model(&DistributedQuery{}).Count(&queriesCount).Error)
	require.NoError(t, db.Model(&NodeQuery{}).Count(&nodesCount).Error)
	require.NoError(t, db.Model(&DistributedQueryTarget{}).Count(&targetsCount).Error)
	require.EqualValues(t, 2, queriesCount)
	require.EqualValues(t, 0, nodesCount)
	require.EqualValues(t, 0, targetsCount)
}
