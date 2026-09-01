package alerts

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/settings"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPruneHistoryWithRetention(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// One old row (40 days), one recent (5 days), one exactly on the
	// 30-day boundary edge (29 days).
	old := AlertHistory{RuleName: "old"}
	old.CreatedAt = now.AddDate(0, 0, -40)
	recent := AlertHistory{RuleName: "recent"}
	recent.CreatedAt = now.AddDate(0, 0, -5)
	edge := AlertHistory{RuleName: "edge"}
	edge.CreatedAt = now.AddDate(0, 0, -29)
	for _, h := range []AlertHistory{old, recent, edge} {
		h := h
		if err := m.DB.Create(&h).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	deleted, err := m.PruneHistoryWithRetention(30, now)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deletion (only the 40-day row), got %d", deleted)
	}
	rows, _ := m.RecentHistory(10)
	if len(rows) != 2 {
		t.Fatalf("recent + edge must survive, got %d rows", len(rows))
	}

	// Zero retention must never delete everything (cutoff guard).
	if _, err := m.PruneHistoryWithRetention(0, now); err != nil {
		t.Fatalf("zero retention: %v", err)
	}
	rows, _ = m.RecentHistory(10)
	if len(rows) != 2 {
		t.Fatalf("zero retention must be a no-op, got %d rows", len(rows))
	}
}

func TestAlertHistoryRetentionSetting(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	mgr := settings.NewSettings(db)

	// Absent setting → default.
	if got := mgr.AlertHistoryRetentionDays(); got != settings.DefaultAlertHistoryRetentionDays {
		t.Fatalf("absent setting: got %d want %d", got, settings.DefaultAlertHistoryRetentionDays)
	}

	// Invalid (zero / negative) → default, never an unbounded table.
	if err := mgr.NewIntegerValue("tls", settings.AlertHistoryRetentionDays, 0, settings.NoEnvironmentID); err != nil {
		t.Fatalf("seed zero: %v", err)
	}
	if got := mgr.AlertHistoryRetentionDays(); got != settings.DefaultAlertHistoryRetentionDays {
		t.Fatalf("zero setting: got %d want default %d", got, settings.DefaultAlertHistoryRetentionDays)
	}

	// Valid override honored.
	if err := mgr.SetInteger(90, "tls", settings.AlertHistoryRetentionDays, settings.NoEnvironmentID); err != nil {
		t.Fatalf("set override: %v", err)
	}
	if got := mgr.AlertHistoryRetentionDays(); got != 90 {
		t.Fatalf("override: got %d want 90", got)
	}
}
