package auditlog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuditRetentionBoundsAndPhysicalDeletion(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -90)
	rows := make([]AuditLog, retentionBatchSize+1)
	for i := range rows {
		rows[i] = AuditLog{Model: gorm.Model{CreatedAt: cutoff.Add(-time.Second)}, Service: "tls", LogType: LogTypeNode}
	}
	require.NoError(t, db.CreateInBatches(&rows, 100).Error)
	require.NoError(t, db.Delete(&rows[0]).Error)
	boundary := AuditLog{Model: gorm.Model{CreatedAt: cutoff}, LogType: LogTypeLogin}
	require.NoError(t, db.Create(&boundary).Error)
	for _, invalid := range []int64{0, -1, 36501} {
		_, err := m.PruneBatch(context.Background(), invalid, now)
		require.Error(t, err)
	}
	deleted, err := m.PruneBatch(context.Background(), 90, now)
	require.NoError(t, err)
	require.EqualValues(t, retentionBatchSize, deleted)
	deleted, err = m.PruneBatch(context.Background(), 90, now)
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	deleted, err = m.PruneBatch(context.Background(), 90, now)
	require.NoError(t, err)
	require.Zero(t, deleted)
	var remaining []AuditLog
	require.NoError(t, db.Unscoped().Find(&remaining).Error)
	require.Len(t, remaining, 1)
	require.Equal(t, boundary.ID, remaining[0].ID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = m.PruneBatch(ctx, 90, now)
	require.ErrorIs(t, err, context.Canceled)
}

func TestAuditActionTypes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := CreateAuditLogManager(db, "tls", true)
	require.NoError(t, err)
	m.NewEnroll("NODE", "127.0.0.1", 1)
	m.FailedEnroll("127.0.0.1", "env", "invalid secret", 1)
	m.QueryAction("alice", "complete query", "127.0.0.1", 1)
	var rows []AuditLog
	require.NoError(t, db.Order("id").Find(&rows).Error)
	require.Len(t, rows, 3)
	require.EqualValues(t, LogTypeEnroll, rows[0].LogType)
	require.EqualValues(t, LogTypeNode, rows[1].LogType)
	require.EqualValues(t, LogTypeQuery, rows[2].LogType)
	_, supported := LogTypes[LogTypeEnroll]
	require.True(t, supported)
}

func TestFailedOsctrld(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := CreateAuditLogManager(db, "tls", true)
	require.NoError(t, err)
	m.FailedOsctrld("203.0.113.5", "prod", "invalid secret", 7)
	var rows []AuditLog
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	require.EqualValues(t, LogTypeNode, rows[0].LogType)
	require.EqualValues(t, SeverityWarning, rows[0].Severity)
	require.EqualValues(t, 7, rows[0].EnvironmentID)
	require.Equal(t, "203.0.113.5", rows[0].SourceIP)
	require.Equal(t, "failed osctrld secret for env prod: invalid secret", rows[0].Line)
}
