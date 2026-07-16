package handlers

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newPostureTestHandler(t *testing.T) *HandlersTLS {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return &HandlersTLS{Posture: posture.NewPostureManager(db)}
}

func TestIngestPostureAggregatesRowsFromSameResultBatch(t *testing.T) {
	h := newPostureTestHandler(t)
	results := []types.LogResultData{
		{
			Name:    posture.QueryPrefix + "users",
			Columns: json.RawMessage(`{"username":"alice","uid":"501"}`),
		},
		{
			Name:    posture.QueryPrefix + "users",
			Columns: json.RawMessage(`{"username":"bob","uid":"502"}`),
		},
	}

	h.ingestPosture(results, "node-a", "dev")

	records, err := h.Posture.GetByNode("node-a")
	if err != nil {
		t.Fatalf("get posture: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one posture category, got %d", len(records))
	}
	if records[0].RowCount != 2 {
		t.Fatalf("expected two rows in aggregated posture result, got %d", records[0].RowCount)
	}

	var summary []map[string]string
	if err := json.Unmarshal([]byte(records[0].Summary), &summary); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if len(summary) != 2 || summary[0]["username"] != "alice" || summary[1]["username"] != "bob" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestIngestPostureStoresEmptySnapshotResults(t *testing.T) {
	h := newPostureTestHandler(t)
	results := []types.LogResultData{
		{
			Name:    posture.QueryPrefix + "empty",
			Columns: nil,
		},
	}

	h.ingestPosture(results, "node-a", "dev")

	records, err := h.Posture.GetByNode("node-a")
	if err != nil {
		t.Fatalf("get posture: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one posture category, got %d", len(records))
	}
	if records[0].RowCount != 0 {
		t.Fatalf("expected zero rows for empty snapshot, got %d", records[0].RowCount)
	}
	if records[0].Summary != "[]" {
		t.Fatalf("expected empty JSON array summary, got %q", records[0].Summary)
	}
}
