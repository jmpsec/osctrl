package logging

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/backend"
)

func newTestLoggerDB(t *testing.T) *LoggerDB {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	logDB, err := CreateLoggerDB(&backend.DBManager{Conn: db})
	if err != nil {
		t.Fatalf("CreateLoggerDB: %v", err)
	}
	return logDB
}

func statusBatch(t *testing.T, messages []string) []byte {
	t.Helper()
	type line struct {
		HostIdentifier string `json:"hostIdentifier"`
		Message        string `json:"message"`
		Line           int    `json:"line"`
	}
	lines := make([]line, len(messages))
	for i, m := range messages {
		lines[i] = line{HostIdentifier: "node-a", Message: m, Line: i}
	}
	b, err := json.Marshal(lines)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func numbered(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%03d", prefix, i)
	}
	return out
}

// A batch larger than one INSERT must land completely, across several
// multi-row statements.
func TestStatusLogsSpanningSeveralInsertBatches(t *testing.T) {
	logDB := newTestLoggerDB(t)
	want := numbered("line", 2*logInsertBatchSize+7)

	logDB.Status(statusBatch(t, want), "prod", "node-a", false)

	var count int64
	logDB.Database.Conn.Model(&OsqueryStatusData{}).Count(&count)
	if count != int64(len(want)) {
		t.Fatalf("stored %d status rows, want %d", count, len(want))
	}
}

// Readers order by created_at alone. A multi-row INSERT would give every row
// the same timestamp and let the lines of one batch come back shuffled; each
// row must get its own, in the order osquery sent them.
func TestStatusLogsKeepSendOrder(t *testing.T) {
	logDB := newTestLoggerDB(t)
	want := numbered("line", 3*logInsertBatchSize)

	logDB.Status(statusBatch(t, want), "prod", "node-a", false)

	var rows []OsqueryStatusData
	if err := logDB.Database.Conn.Order("created_at").Find(&rows).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != len(want) {
		t.Fatalf("read %d rows, want %d", len(rows), len(want))
	}
	for i, r := range rows {
		if r.Message != want[i] {
			t.Fatalf("row %d = %q, want %q: batch order not preserved", i, r.Message, want[i])
		}
		if i > 0 && !r.CreatedAt.After(rows[i-1].CreatedAt) {
			t.Fatalf("row %d created_at %v not after row %d's %v", i, r.CreatedAt, i-1, rows[i-1].CreatedAt)
		}
	}
	// The newest-first reader the UI uses must see the same order reversed.
	got, err := logDB.StatusLogsLimit("node-a", "prod", 5)
	if err != nil {
		t.Fatalf("StatusLogsLimit: %v", err)
	}
	for i, r := range got {
		if r.Message != want[len(want)-1-i] {
			t.Fatalf("newest-first row %d = %q, want %q", i, r.Message, want[len(want)-1-i])
		}
	}
}

// The batch is one transaction, so one unstorable row would otherwise drop
// every line sent with it. Row-by-row inserts only ever lost the bad row, and
// that must still hold — without the rest being written twice.
func TestStatusLogsBadRowDoesNotDropTheBatch(t *testing.T) {
	logDB := newTestLoggerDB(t)
	// SQLite stores almost anything, so a trigger stands in for a value the
	// production database would refuse.
	if err := logDB.Database.Conn.Exec(`CREATE TRIGGER reject_poison BEFORE INSERT ON osquery_status_data
		WHEN NEW.message = 'poison' BEGIN SELECT RAISE(ABORT, 'poison row'); END`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	// Put the bad row in a later INSERT, so earlier ones had already
	// succeeded inside the transaction when it rolled back.
	msgs := numbered("line", logInsertBatchSize+10)
	msgs[logInsertBatchSize+3] = "poison"

	logDB.Status(statusBatch(t, msgs), "prod", "node-a", false)

	var rows []OsqueryStatusData
	logDB.Database.Conn.Order("created_at").Find(&rows)
	if len(rows) != len(msgs)-1 {
		t.Fatalf("stored %d rows, want %d: everything except the poison row", len(rows), len(msgs)-1)
	}
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		if r.Message == "poison" {
			t.Fatal("poison row was stored")
		}
		if seen[r.Message] {
			t.Fatalf("row %q stored twice: the rolled-back batch leaked", r.Message)
		}
		seen[r.Message] = true
	}
}

func TestResultLogsAreBatched(t *testing.T) {
	logDB := newTestLoggerDB(t)
	type result struct {
		Name           string            `json:"name"`
		HostIdentifier string            `json:"hostIdentifier"`
		Columns        map[string]string `json:"columns"`
	}
	n := logInsertBatchSize + 1
	batch := make([]result, n)
	for i := range batch {
		batch[i] = result{Name: "pack_uptime", HostIdentifier: "node-a", Columns: map[string]string{"seq": fmt.Sprint(i)}}
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	logDB.Result(data, "prod", "node-a", false)

	var rows []OsqueryResultData
	logDB.Database.Conn.Order("created_at").Find(&rows)
	if len(rows) != n {
		t.Fatalf("stored %d result rows, want %d", len(rows), n)
	}
	for i, r := range rows {
		if want := fmt.Sprintf(`{"seq":"%d"}`, i); r.Columns != want {
			t.Fatalf("row %d columns = %s, want %s", i, r.Columns, want)
		}
		if r.UUID != "NODE-A" || r.Environment != "prod" {
			t.Fatalf("row %d = %+v, fields not carried over", i, r)
		}
	}
}

func TestEmptyLogBatchIsANoop(t *testing.T) {
	logDB := newTestLoggerDB(t)
	logDB.Status([]byte(`[]`), "prod", "node-a", false)
	logDB.Result([]byte(`[]`), "prod", "node-a", false)

	var status, result int64
	logDB.Database.Conn.Model(&OsqueryStatusData{}).Count(&status)
	logDB.Database.Conn.Model(&OsqueryResultData{}).Count(&result)
	if status != 0 || result != 0 {
		t.Fatalf("empty batches stored %d status / %d result rows", status, result)
	}
}
