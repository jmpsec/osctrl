package health

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	return NewManager(db)
}

func TestReportUpsertsOneRowPerService(t *testing.T) {
	m := testManager(t)
	started := time.Now().Add(-time.Hour)

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Report(ServiceStatus{
			Service:    "tls",
			Version:    "0.5.8",
			StartedAt:  started,
			ReportedAt: time.Now(),
			Goroutines: 40 + i,
			Payload:    `{"alerts":{"enabled":true}}`,
		}))
	}

	var count int64
	require.NoError(t, m.DB.Model(&ServiceStatus{}).Where("service = ?", "tls").Count(&count).Error)
	require.EqualValues(t, 1, count, "heartbeat must upsert, not append")

	row, err := m.Get("tls")
	require.NoError(t, err)
	require.Equal(t, "0.5.8", row.Version)
	require.Equal(t, 42, row.Goroutines, "last write wins")
	require.Equal(t, `{"alerts":{"enabled":true}}`, row.Payload)
	require.WithinDuration(t, started, row.StartedAt, time.Second)
}

func TestGetUnknownServiceReturnsErrNotReporting(t *testing.T) {
	m := testManager(t)
	_, err := m.Get("tls")
	require.ErrorIs(t, err, ErrNotReporting)
}
