package carves

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
)

func TestPruneCompletedBeforeKeepsActiveAndRecentCarves(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateFileCarves(db, config.CarverDB, nil)

	now := time.Now()
	old := now.Add(-72 * time.Hour)
	oldCarve := CarvedFile{CarveID: "old", SessionID: "old", Status: StatusCompleted, UpdatedAt: old, CreatedAt: old, Archived: true, ArchivePath: "/nonexistent/osctrl-archive.tar.gz"}
	recentCarve := CarvedFile{CarveID: "recent", SessionID: "recent", Status: StatusCompleted, UpdatedAt: now, CreatedAt: now}
	activeCarve := CarvedFile{CarveID: "active", SessionID: "active", Status: StatusInProgress, UpdatedAt: old, CreatedAt: old}
	require.NoError(t, db.Create(&oldCarve).Error)
	require.NoError(t, db.Create(&recentCarve).Error)
	require.NoError(t, db.Create(&activeCarve).Error)
	require.NoError(t, db.Create(&CarvedBlock{SessionID: "old", BlockID: 0, Data: "old-block"}).Error)
	require.NoError(t, db.Create(&CarvedBlock{SessionID: "recent", BlockID: 0, Data: "recent-block"}).Error)

	deleted, err := m.PruneCompletedBefore(now.Add(-24 * time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)

	var carveCount, blockCount int64
	require.NoError(t, db.Model(&CarvedFile{}).Count(&carveCount).Error)
	require.NoError(t, db.Model(&CarvedBlock{}).Count(&blockCount).Error)
	require.EqualValues(t, 2, carveCount)
	require.EqualValues(t, 1, blockCount)

	// A concurrent replica (or a second run) finds nothing left to delete.
	deleted, err = m.PruneCompletedBefore(now.Add(-24 * time.Hour))
	require.NoError(t, err)
	require.Zero(t, deleted)
}
