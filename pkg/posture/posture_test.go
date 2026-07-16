package posture

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *PostureManager {
	t.Helper()
	dsn := "file:posture_" + t.Name() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return NewPostureManager(db)
}

func marshalRows(t *testing.T, count int) json.RawMessage {
	t.Helper()
	rows := make([]map[string]interface{}, count)
	for i := range rows {
		rows[i] = map[string]interface{}{"id": i, "name": fmt.Sprintf("row-%d", i)}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal rows: %v", err)
	}
	return b
}

func TestIngestResultTruncatesSummaryWithoutLosingRowCount(t *testing.T) {
	pm := newTestManager(t)
	if err := pm.IngestResult("node-a", "dev", QueryPrefix+"packages", marshalRows(t, 105)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	records, err := pm.GetByNode("node-a")
	if err != nil {
		t.Fatalf("get posture: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RowCount != 105 {
		t.Fatalf("expected row count 105, got %d", records[0].RowCount)
	}
	var summary []json.RawMessage
	if err := json.Unmarshal([]byte(records[0].Summary), &summary); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if len(summary) != 100 {
		t.Fatalf("expected 100 summary rows, got %d", len(summary))
	}
}

func TestIngestResultStoresEmptyColumnsAsEmptySnapshot(t *testing.T) {
	pm := newTestManager(t)
	if err := pm.IngestResult("node-a", "dev", QueryPrefix+"empty", nil); err != nil {
		t.Fatalf("ingest empty snapshot: %v", err)
	}

	records, err := pm.GetByNode("node-a")
	if err != nil {
		t.Fatalf("get posture: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RowCount != 0 {
		t.Fatalf("expected row count 0, got %d", records[0].RowCount)
	}
	if records[0].Summary != "[]" {
		t.Fatalf("expected empty JSON array summary, got %q", records[0].Summary)
	}
}

func TestIngestResultAtomicallyUpsertsOneRecord(t *testing.T) {
	pm := newTestManager(t)
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	payloads := make([]json.RawMessage, workers)
	for i := range payloads {
		payloads[i] = marshalRows(t, i+1)
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			errs <- pm.IngestResult("node-a", "env", QueryPrefix+"users", payloads[i])
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ingest: %v", err)
		}
	}

	var count int64
	if err := pm.DB.Model(&NodePosture{}).Where("node_uuid = ? AND category = ?", "NODE-A", "users").Count(&count).Error; err != nil {
		t.Fatalf("count posture rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one node/category row, got %d", count)
	}
}

func TestIngestResultUpdatesMutableFieldsAndPreservesFirstSeen(t *testing.T) {
	pm := newTestManager(t)
	name := QueryPrefix + "users"
	if err := pm.IngestResult("node-a", "old-env", name, marshalRows(t, 1)); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	before, err := pm.GetByNode("node-a")
	if err != nil || len(before) != 1 {
		t.Fatalf("get initial posture: records=%d err=%v", len(before), err)
	}
	time.Sleep(time.Millisecond)
	if err := pm.IngestResult("node-a", "new-env", name, marshalRows(t, 2)); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	after, err := pm.GetByNode("node-a")
	if err != nil || len(after) != 1 {
		t.Fatalf("get updated posture: records=%d err=%v", len(after), err)
	}
	if after[0].Environment != "new-env" || after[0].RowCount != 2 || after[0].QueryName != name {
		t.Fatalf("mutable fields not updated: %+v", after[0])
	}
	if !after[0].FirstSeen.Equal(before[0].FirstSeen) {
		t.Fatalf("first_seen changed from %s to %s", before[0].FirstSeen, after[0].FirstSeen)
	}
	if !after[0].LastSeen.After(before[0].LastSeen) {
		t.Fatalf("last_seen did not advance from %s to %s", before[0].LastSeen, after[0].LastSeen)
	}
}

func TestIngestResultRejectsMalformedColumns(t *testing.T) {
	pm := newTestManager(t)
	for _, columns := range []json.RawMessage{
		json.RawMessage(`{"broken"`),
		json.RawMessage(`[null]`),
		json.RawMessage(`[1]`),
		json.RawMessage(`["row"]`),
		json.RawMessage(`[[]]`),
	} {
		if err := pm.IngestResult("node-a", "dev", QueryPrefix+"users", columns); err == nil {
			t.Errorf("expected malformed columns error for %s", columns)
		}
	}
}

type legacyNodePosture struct {
	ID          uint `gorm:"primarykey"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	NodeUUID    string `gorm:"index:idx_posture_node,composite"`
	Environment string
	Category    string `gorm:"index:idx_posture_node,composite;type:varchar(64)"`
	QueryName   string `gorm:"type:varchar(255)"`
	RowCount    int
	Summary     string `gorm:"type:text"`
	FirstSeen   time.Time
	LastSeen    time.Time
}

func (legacyNodePosture) TableName() string { return "node_posture" }

func TestMigrateNodePostureDeduplicatesLegacyRowsBeforeUniqueIndex(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:posture_migration?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&legacyNodePosture{}); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	oldTime := time.Now().Add(-time.Hour)
	newTime := time.Now()
	rows := []legacyNodePosture{
		{NodeUUID: "NODE-A", Category: "users", Summary: `[{"old":true}]`, UpdatedAt: oldTime},
		{NodeUUID: "NODE-A", Category: "users", Summary: `[{"new":true}]`, UpdatedAt: newTime},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("insert legacy duplicates: %v", err)
	}

	if err := migrateNodePosture(db); err != nil {
		t.Fatalf("migrate posture table: %v", err)
	}
	var retained []NodePosture
	if err := db.Find(&retained).Error; err != nil {
		t.Fatalf("read migrated rows: %v", err)
	}
	if len(retained) != 1 || retained[0].Summary != `[{"new":true}]` {
		t.Fatalf("expected newest duplicate to survive, got %+v", retained)
	}
	duplicate := NodePosture{NodeUUID: "NODE-A", Category: "users"}
	if err := db.Create(&duplicate).Error; err == nil {
		t.Fatal("expected unique node/category index after migration")
	}
	if db.Migrator().HasIndex(&NodePosture{}, "idx_posture_node") {
		t.Fatal("legacy duplicate index still exists after migration")
	}
}

func TestNodePostureUUIDColumnIsBoundedForIndexedBackends(t *testing.T) {
	pm := newTestManager(t)
	typ, err := pm.DB.Migrator().ColumnTypes(&NodePosture{})
	if err != nil {
		t.Fatalf("read posture column metadata: %v", err)
	}
	for _, column := range typ {
		if column.Name() != "node_uuid" {
			continue
		}
		length, ok := column.Length()
		if !ok || length != 36 {
			t.Fatalf("node_uuid column length = %d, %v; want 36, true", length, ok)
		}
		return
	}
	t.Fatal("node_uuid column not found")
}

func TestMigrateNodePostureHandlesMoreDuplicatesThanSQLBindLimit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:posture_large_migration?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&legacyNodePosture{}); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	rows := make([]legacyNodePosture, 33_000)
	for i := range rows {
		rows[i] = legacyNodePosture{NodeUUID: "NODE-A", Category: "users", UpdatedAt: time.Unix(int64(i), 0)}
	}
	if err := db.CreateInBatches(rows, 100).Error; err != nil {
		t.Fatalf("insert legacy duplicates: %v", err)
	}

	if err := migrateNodePosture(db); err != nil {
		t.Fatalf("migrate posture table: %v", err)
	}
	var count int64
	if err := db.Model(&NodePosture{}).Count(&count).Error; err != nil {
		t.Fatalf("count migrated rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one retained row, got %d", count)
	}
}

func TestMigrateNodePostureIsIdempotentDuringConcurrentStartup(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "posture.db") + "?_busy_timeout=5000&_journal_mode=WAL"
	db1, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open first sqlite connection: %v", err)
	}
	db2, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open second sqlite connection: %v", err)
	}
	if err := db1.AutoMigrate(&legacyNodePosture{}); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	if err := db1.Create(&[]legacyNodePosture{
		{NodeUUID: "NODE-A", Category: "users", UpdatedAt: time.Now().Add(-time.Minute)},
		{NodeUUID: "NODE-A", Category: "users", UpdatedAt: time.Now()},
	}).Error; err != nil {
		t.Fatalf("insert legacy duplicates: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, db := range []*gorm.DB{db1, db2} {
		go func(db *gorm.DB) {
			<-start
			errs <- migrateNodePosture(db)
		}(db)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent migration: %v", err)
		}
	}
	if !db1.Migrator().HasIndex(&NodePosture{}, "idx_posture_node_category") {
		t.Fatal("unique index missing after concurrent migration")
	}
}
