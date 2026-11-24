package fileexplorer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPruneInactiveBeforeKeepsActiveAndRecentSessions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m := NewManager(db, nil)

	now := time.Now()
	old := now.Add(-72 * time.Hour)
	inactive := Session{EnvironmentID: 1, NodeID: 1, NodeUUID: "n", Creator: "u", Root: "/", Active: false, UpdatedAt: old, CreatedAt: old}
	recent := Session{EnvironmentID: 1, NodeID: 1, NodeUUID: "n", Creator: "u", Root: "/", Active: false, UpdatedAt: now, CreatedAt: now}
	active := Session{EnvironmentID: 1, NodeID: 1, NodeUUID: "n", Creator: "u", Root: "/", Active: true, UpdatedAt: old, CreatedAt: old}
	require.NoError(t, db.Create(&inactive).Error)
	require.NoError(t, db.Create(&recent).Error)
	require.NoError(t, db.Create(&active).Error)
	require.NoError(t, db.Model(&inactive).UpdateColumn("active", false).Error)
	require.NoError(t, db.Model(&recent).UpdateColumn("active", false).Error)
	require.NoError(t, db.Create(&Request{SessionID: inactive.ID, Action: "ls", Path: "/"}).Error)
	require.NoError(t, db.Create(&Request{SessionID: recent.ID, Action: "ls", Path: "/"}).Error)

	deleted, err := m.PruneInactiveBefore(now.Add(-24 * time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)

	var sessions, requests int64
	require.NoError(t, db.Model(&Session{}).Count(&sessions).Error)
	require.NoError(t, db.Model(&Request{}).Count(&requests).Error)
	require.EqualValues(t, 2, sessions)
	require.EqualValues(t, 1, requests)
}
