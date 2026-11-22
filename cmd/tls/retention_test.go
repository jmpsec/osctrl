package main

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/settings"
)

func TestPruneLogRetentionOnceUsesPerEnvironmentSetting(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	dbManager := &backend.DBManager{Conn: db}

	envs := environments.CreateEnvironment(db)
	require.NoError(t, envs.Create(&environments.TLSEnvironment{
		Name: "prod",
		UUID: uuid.NewString(),
	}))

	settingsMgr := settings.NewSettings(db)
	require.NoError(t, settingsMgr.NewIntegerValue(
		config.ServiceTLS, settings.LogRetentionDays, 1, settings.NoEnvironmentID,
	))

	dbLogger, err := logging.CreateLoggerDB(dbManager)
	require.NoError(t, err)
	loggerTLS := logging.CreateLoggerTLSWith(
		map[uint]*logging.MultiExporter{0: logging.NewMultiExporter(dbLogger)}, nil, nil,
	)

	now := time.Now()
	old := now.Add(-72 * time.Hour)
	require.NoError(t, db.Create(&logging.OsqueryStatusData{
		UUID: "node-a", Environment: "prod", Line: "old", CreatedAt: old,
	}).Error)
	require.NoError(t, db.Create(&logging.OsqueryStatusData{
		UUID: "node-a", Environment: "prod", Line: "new", CreatedAt: now,
	}).Error)

	total := pruneLogRetentionOnce(loggerTLS, settingsMgr, envs)
	require.EqualValues(t, 1, total.StatusLogs)

	var remaining int64
	require.NoError(t, db.Model(&logging.OsqueryStatusData{}).Where("environment = ?", "prod").Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)
}
