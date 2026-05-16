package handlers

import (
	"encoding/json"
	"testing"
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
