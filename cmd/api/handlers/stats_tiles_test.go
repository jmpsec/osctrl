package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
)

// TestActivityTileDays covers the ?days parser/clamper for the tile endpoints.
// Default 1, invalid->1, below 1->1, capped at DefaultRetentionDays.
func TestActivityTileDays(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 1},
		{"0", 1},
		{"-3", 1},
		{"abc", 1},
		{"1", 1},
		{"3", 3},
		{"7", 7},
		{"8", activity.DefaultRetentionDays}, // over retention clamps down
		{"99", activity.DefaultRetentionDays},
	}
	for _, c := range cases {
		if got := activityTileDays(c.in); got != c.want {
			t.Fatalf("activityTileDays(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestNodeTileSeriesJSONShape locks the snake_case contract the SPA depends on
// for the Redis-backed tile endpoints. A field rename in Go must not silently
// break the frontend bindings.
func TestNodeTileSeriesJSONShape(t *testing.T) {
	series := activity.NodeTileSeries{
		Start:         time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		BucketSeconds: activity.BucketSeconds,
		Enroll:        []uint16{0, 1},
		Config:        []uint16{2, 0},
		Status:        []uint16{0, 3},
		Result:        []uint16{4, 5},
		QueryRead:     []uint16{6, 0},
		QueryWrite:    []uint16{0, 7},
		Total:         []uint16{12, 16},
	}
	b, err := json.Marshal(series)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"start", "bucket_seconds", "enroll", "config", "status", "result", "query_read", "query_write", "total"} {
		if _, ok := m[key]; !ok {
			t.Errorf("NodeTileSeries JSON missing field %q", key)
		}
	}
}
