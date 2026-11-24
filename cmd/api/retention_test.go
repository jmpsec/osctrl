package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
)

func TestPruneDataRetentionOnceRunsQueryRetention(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)

	settingsMgr := settings.NewSettings(db)
	require.NoError(t, settingsMgr.NewIntegerValue(
		config.ServiceAPI, settings.QueryMetadataRetentionDays, 1, settings.NoEnvironmentID,
	))
	queriesMgr := queries.CreateQueries(db)

	now := time.Now()
	old := now.Add(-72 * time.Hour)
	require.NoError(t, db.Create(&queries.DistributedQuery{
		Name: "old", Active: false, Completed: true, CreatedAt: old, UpdatedAt: old,
	}).Error)

	stats := pruneDataRetentionOnce(
		settingsMgr, nil, nil, queriesMgr, nil, nil, nil,
	)
	require.EqualValues(t, 1, stats.Queries)
}
