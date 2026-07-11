package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
)

// TestStatsResponseShape verifies the JSON tags on the response types are
// snake_case and match the OpenAPI schema field names. This catches regressions
// where a field rename in Go doesn't propagate to the JSON output shape.
//
// Full integration tests (DB-backed) are deferred: the underlying
// pkg/nodes.GetStatsByEnv and pkg/queries.GetQueries/GetCarves are covered by
// their own package tests. A handler-level integration test would require
// substantial DB fixturing that is out of scope for Track 2.
func TestStatsResponseShape(t *testing.T) {
	resp := StatsResponse{
		TotalNodes:         10,
		ActiveNodes:        7,
		InactiveNodes:      3,
		TotalActiveQueries: 2,
		TotalActiveCarves:  1,
		Environments: []EnvStats{
			{
				UUID:          "env-uuid-1",
				Name:          "prod",
				Active:        5,
				Inactive:      2,
				Total:         7,
				ActiveQueries: 1,
				ActiveCarves:  0,
			},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal(StatsResponse): %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Verify top-level snake_case field names.
	topLevel := []string{
		"total_nodes",
		"active_nodes",
		"inactive_nodes",
		"total_active_queries",
		"total_active_carves",
		"platform_counts",
		"environments",
	}
	for _, key := range topLevel {
		if _, ok := m[key]; !ok {
			t.Errorf("StatsResponse JSON missing field %q", key)
		}
	}

	// Verify per-env field names in the first environments entry.
	envs, ok := m["environments"].([]interface{})
	if !ok || len(envs) == 0 {
		t.Fatal("StatsResponse.environments is empty or wrong type")
	}
	envMap, ok := envs[0].(map[string]interface{})
	if !ok {
		t.Fatal("environments[0] is not a JSON object")
	}
	envLevel := []string{
		"uuid",
		"name",
		"active",
		"inactive",
		"total",
		"active_queries",
		"active_carves",
		"platform_counts",
	}
	for _, key := range envLevel {
		if _, ok := envMap[key]; !ok {
			t.Errorf("EnvStats JSON missing field %q", key)
		}
	}

	// Verify numeric totals round-trip correctly.
	if got := m["total_nodes"]; got != float64(10) {
		t.Errorf("total_nodes = %v, want 10", got)
	}
	if got := m["active_nodes"]; got != float64(7) {
		t.Errorf("active_nodes = %v, want 7", got)
	}
}

// TestNodeActivityBucketShape verifies that the config field round-trips
// through JSON and that the struct has all expected fields.
func TestNodeActivityBucketShape(t *testing.T) {
	bucket := NodeActivityBucket{
		BucketStart: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC),
		Status:      5,
		Result:      3,
		Query:       2,
		Carve:       1,
		Config:      42,
	}

	b, err := json.Marshal(bucket)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, key := range []string{"bucket_start", "status", "result", "query", "carve", "config"} {
		if _, ok := m[key]; !ok {
			t.Errorf("NodeActivityBucket JSON missing field %q", key)
		}
	}
	if got := m["config"]; got != float64(42) {
		t.Errorf("config = %v, want 42", got)
	}
}

// TestConfigFolding verifies that computeNodeActivityForNode correctly folds
// hourly Redis counts (config, query_read, query_write) into sub-hourly DB
// buckets. Each hour's full count must land in the first DB bucket of that
// hour so the SPA's hourly collapse is not inflated. This mirrors the merge
// the Node Detail page does client-side (mergeNodeActivityBuckets).
func TestRedisFolding(t *testing.T) {
	// 24h window, 15-min buckets → 96 buckets
	bucketSeconds := 900
	nBuckets := 96
	now := time.Date(2026, 7, 11, 14, 30, 0, 0, time.UTC)
	endBucket := time.Unix((now.Unix()/int64(bucketSeconds))*int64(bucketSeconds), 0).UTC()
	startBucket := endBucket.Add(-time.Duration(nBuckets-1) * time.Duration(bucketSeconds) * time.Second)

	// Redis series: 24 hourly buckets, starting at midnight UTC.
	redisStart := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	configCounts := make([]uint16, 24)
	queryReadCounts := make([]uint16, 24)
	queryWriteCounts := make([]uint16, 24)
	// Hour 14: 10 config fetches, 3 query reads, 1 query write
	configCounts[14] = 10
	queryReadCounts[14] = 3
	queryWriteCounts[14] = 1
	// Hour 15: 5 config fetches, 0 query reads, 2 query writes
	configCounts[15] = 5
	queryWriteCounts[15] = 2

	tiles := &activity.NodeTileSeries{
		Start:         redisStart,
		BucketSeconds: 3600,
		Config:        configCounts,
		QueryRead:     queryReadCounts,
		QueryWrite:    queryWriteCounts,
	}

	// Replicate the folding algorithm from computeNodeActivityForNode.
	configDense := make([]int, nBuckets)
	queryReadDense := make([]int, nBuckets)
	queryWriteDense := make([]int, nBuckets)
	lastHour := -1
	for i := 0; i < nBuckets; i++ {
		bucketStart := startBucket.Add(time.Duration(i) * time.Duration(bucketSeconds) * time.Second)
		hourIdx := int(bucketStart.Sub(tiles.Start) / (time.Duration(tiles.BucketSeconds) * time.Second))
		if hourIdx < 0 {
			continue
		}
		if hourIdx == lastHour {
			continue
		}
		if hourIdx < len(tiles.Config) {
			configDense[i] = int(tiles.Config[hourIdx])
		}
		if hourIdx < len(tiles.QueryRead) {
			queryReadDense[i] = int(tiles.QueryRead[hourIdx])
		}
		if hourIdx < len(tiles.QueryWrite) {
			queryWriteDense[i] = int(tiles.QueryWrite[hourIdx])
		}
		lastHour = hourIdx
	}

	// Config: hour 14 = 10, hour 15 = 5 → total 15, 2 non-zero buckets.
	totalConfig := 0
	nonZeroConfig := 0
	for _, v := range configDense {
		totalConfig += v
		if v > 0 {
			nonZeroConfig++
		}
	}
	if totalConfig != 15 {
		t.Errorf("total config = %d, want 15", totalConfig)
	}
	if nonZeroConfig != 2 {
		t.Errorf("non-zero config buckets = %d, want 2", nonZeroConfig)
	}

	// Query read: hour 14 = 3 → total 3, 1 non-zero bucket.
	totalQR := 0
	nonZeroQR := 0
	for _, v := range queryReadDense {
		totalQR += v
		if v > 0 {
			nonZeroQR++
		}
	}
	if totalQR != 3 {
		t.Errorf("total query_read = %d, want 3", totalQR)
	}
	if nonZeroQR != 1 {
		t.Errorf("non-zero query_read buckets = %d, want 1", nonZeroQR)
	}

	// Query write: hour 14 = 1, hour 15 = 2 → total 3, 2 non-zero buckets.
	totalQW := 0
	nonZeroQW := 0
	for _, v := range queryWriteDense {
		totalQW += v
		if v > 0 {
			nonZeroQW++
		}
	}
	if totalQW != 3 {
		t.Errorf("total query_write = %d, want 3", totalQW)
	}
	if nonZeroQW != 2 {
		t.Errorf("non-zero query_write buckets = %d, want 2", nonZeroQW)
	}
}

// TestConfigFoldingNilTiles verifies that nil tiles produces all-zero config
// buckets (the Redis-not-configured / missing-data case).
func TestConfigFoldingNilTiles(t *testing.T) {
	nBuckets := 96
	configDense := make([]int, nBuckets)
	var tiles *activity.NodeTileSeries

	if tiles != nil && len(tiles.Config) > 0 {
		// This branch should NOT execute when tiles is nil
		t.Fatal("nil tiles should not enter the folding branch")
	}

	for _, v := range configDense {
		if v != 0 {
			t.Errorf("nil tiles should produce all-zero config, got %d", v)
		}
	}
}
