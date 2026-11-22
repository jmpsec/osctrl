package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPruneEnvironmentDeletesOnlyOldRows(t *testing.T) {
	logDB := newTestLoggerDB(t)
	now := time.Now()
	old := now.Add(-72 * time.Hour)

	require.NoError(t, logDB.Database.Conn.Create(&OsqueryStatusData{
		UUID: "node-a", Environment: "prod", Line: "old", CreatedAt: old,
	}).Error)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryStatusData{
		UUID: "node-a", Environment: "prod", Line: "new", CreatedAt: now,
	}).Error)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryResultData{
		UUID: "node-a", Environment: "prod", Name: "q", Columns: "[]", CreatedAt: old,
	}).Error)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryResultData{
		UUID: "node-a", Environment: "prod", Name: "q", Columns: "[]", CreatedAt: now,
	}).Error)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryQueryData{
		UUID: "node-a", Environment: "prod", Name: "q", Data: "{}", CreatedAt: old,
	}).Error)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryQueryData{
		UUID: "node-a", Environment: "prod", Name: "q", Data: "{}", CreatedAt: now,
	}).Error)
	// Another environment's old rows must survive.
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryStatusData{
		UUID: "node-b", Environment: "staging", Line: "old", CreatedAt: old,
	}).Error)

	stats, err := logDB.PruneEnvironment("prod", now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.StatusLogs)
	require.EqualValues(t, 1, stats.ResultLogs)
	require.EqualValues(t, 1, stats.QueryLogs)

	count := func(model any, environment string) int64 {
		var n int64
		require.NoError(t, logDB.Database.Conn.Model(model).Where("environment = ?", environment).Count(&n).Error)
		return n
	}
	require.EqualValues(t, 1, count(&OsqueryStatusData{}, "prod"))
	require.EqualValues(t, 1, count(&OsqueryResultData{}, "prod"))
	require.EqualValues(t, 1, count(&OsqueryQueryData{}, "prod"))
	require.EqualValues(t, 1, count(&OsqueryStatusData{}, "staging"))
}

func TestPruneEnvironmentKeepsWorkingWhenOneTableIsMissing(t *testing.T) {
	logDB := newTestLoggerDB(t)
	require.NoError(t, logDB.Database.Conn.Migrator().DropTable(&OsqueryQueryData{}))
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	require.NoError(t, logDB.Database.Conn.Create(&OsqueryStatusData{
		UUID: "node-a", Environment: "prod", Line: "old", CreatedAt: old,
	}).Error)

	stats, err := logDB.PruneEnvironment("prod", now.Add(-24*time.Hour))
	require.Error(t, err)
	require.EqualValues(t, 1, stats.StatusLogs)
}

func TestDBLoggersFindsAndDeduplicatesWrappedExporters(t *testing.T) {
	logDB := newTestLoggerDB(t)
	multi := NewMultiExporterWithStats([]ExporterEntry{
		{SinkID: 1, Exporter: logDB},
		{SinkID: 2, Exporter: logDB},
	})
	logTLS := CreateLoggerTLSWith(map[uint]*MultiExporter{0: multi}, nil, nil)

	got := logTLS.DBLoggers()
	require.Len(t, got, 1)
	require.Same(t, logDB, got[0])
}

func TestDBLoggersFindsLegacyUnwrappedExporter(t *testing.T) {
	logDB := newTestLoggerDB(t)
	logTLS := CreateLoggerTLSWith(map[uint]*MultiExporter{0: NewMultiExporter(logDB)}, nil, nil)

	got := logTLS.DBLoggers()
	require.Len(t, got, 1)
	require.Same(t, logDB, got[0])
}
