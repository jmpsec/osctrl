package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// fakeBackend is a Backend with fixed data, so the tools can be exercised
// without an osctrl-api behind them.
type fakeBackend struct {
	envs   []environments.TLSEnvironment
	nodes  []nodes.OsqueryNode
	tables []types.OsqueryTable
	err    error
}

func (f *fakeBackend) GetEnvironments() ([]environments.TLSEnvironment, error) {
	return f.envs, f.err
}

func (f *fakeBackend) GetStats() (apiclient.StatsResponse, error) {
	return apiclient.StatsResponse{
		TotalNodes:    3,
		ActiveNodes:   2,
		InactiveNodes: 1,
		InactiveHours: 72,
		Environments: []apiclient.EnvStats{
			{Name: "dev", TotalNodes: 3, ActiveNodes: 2, InactiveNodes: 1, InactiveHours: 2,
				PlatformCounts: apiclient.PlatformCounts{Linux: 2, Darwin: 1}},
		},
	}, f.err
}

func TestFleetStatsEnvironmentThreshold(t *testing.T) {
	s := connect(t, &fakeBackend{})
	var out fleetStatsOut
	call(t, s, "fleet_stats", nil, &out)
	if out.InactiveHours != 72 || len(out.Environments) != 1 || out.Environments[0].InactiveHours != 2 {
		t.Fatalf("thresholds lost in MCP response: %+v", out)
	}
}

func (f *fakeBackend) GetNodes(env, target string) ([]nodes.OsqueryNode, error) {
	return f.nodes, f.err
}

func (f *fakeBackend) GetNode(env, identifier string) (nodes.OsqueryNode, error) {
	for _, n := range f.nodes {
		if n.UUID == identifier || n.Hostname == identifier {
			return n, nil
		}
	}
	return nodes.OsqueryNode{}, f.err
}

func (f *fakeBackend) GetNodePosture(env, uuid string) ([]posture.NodePosture, error) {
	return []posture.NodePosture{{Category: "osquery_info"}, {Category: "disk"}, {Category: "disk"}}, nil
}

func (f *fakeBackend) GetNodePostureScore(env, uuid string) (posture.PostureScore, error) {
	return posture.PostureScore{TotalScore: 12, RiskLevel: "medium", PassCount: 3, WarnCount: 1}, nil
}

func (f *fakeBackend) GetOsqueryTables() ([]types.OsqueryTable, error) {
	return f.tables, f.err
}

func (f *fakeBackend) GetQueries(target, env string) ([]queries.DistributedQuery, error) {
	return []queries.DistributedQuery{
		{Name: "query_1", Query: "select * from uptime", Creator: "admin", Executions: 2, Expected: 3, Active: true},
	}, f.err
}

func (f *fakeBackend) GetQueryResults(env, name string, page, pageSize int) (types.QueryResultsResponse, error) {
	return types.QueryResultsResponse{
		Items:      []map[string]any{{"hostname": "box1", "days": 3}},
		Page:       page,
		PageSize:   pageSize,
		TotalItems: 1,
		TotalPages: 1,
	}, f.err
}

func (f *fakeBackend) GetSavedQueries(env string) ([]types.SavedQueryView, error) {
	return []types.SavedQueryView{{Name: "uptime", Query: "select * from uptime"}}, f.err
}

func newFake() *fakeBackend {
	return &fakeBackend{
		envs: []environments.TLSEnvironment{{
			UUID: "env-uuid", Name: "dev", Hostname: "osctrl.example.com", Type: "osquery",
			// Secrets that must never reach the model.
			Secret: "SUPERSECRET", Certificate: "-----BEGIN CERTIFICATE-----",
		}},
		nodes: []nodes.OsqueryNode{
			{UUID: "UUID1", Hostname: "web-01", Platform: "linux", OsqueryVersion: "5.23.1",
				Environment: "dev", LastSeen: time.Now(), CreatedAt: time.Now().Add(-48 * time.Hour)},
			{UUID: "UUID2", Hostname: "mac-02", Platform: "darwin", OsqueryVersion: "5.23.1", Environment: "dev"},
			{UUID: "UUID3", Hostname: "web-03", Platform: "linux", OsqueryVersion: "5.20.0", Environment: "dev"},
		},
		tables: []types.OsqueryTable{
			{Name: "processes", Description: "All running processes", Platforms: []string{"linux", "darwin", "windows"},
				Columns: []types.OsqueryTableColumn{
					{Name: "pid", Type: "BIGINT", Description: "Process ID"},
					{Name: "name", Type: "TEXT", Description: "Process name"},
				}},
			{Name: "launchd", Description: "macOS launch daemons", Platforms: []string{"darwin"}},
		},
	}
}

// connect wires a client to the server over the SDK's in-memory transport,
// exercising the real MCP handshake, schema generation, and dispatch.
func connect(t *testing.T, b Backend) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := sdk.NewInMemoryTransports()

	srv := NewServer(b, "test")
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// call runs a tool and decodes its structured result into out.
func call(t *testing.T, s *sdk.ClientSession, name string, args map[string]any, out any) *sdk.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%s) returned tool error: %+v", name, res.Content)
	}
	if out != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("marshal structured content: %v", err)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s result: %v", name, err)
		}
	}
	return res
}

func TestAllToolsRegistered(t *testing.T) {
	s := connect(t, newFake())
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %s has no description — the model relies on it to choose", tool.Name)
		}
	}
	want := []string{
		"list_environments", "fleet_stats",
		"search_nodes", "get_node",
		"list_osquery_tables", "get_table_schema",
		"list_queries", "list_saved_queries", "get_query_results",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("tool %s not registered", w)
		}
	}
	if len(res.Tools) != len(want) {
		t.Errorf("registered %d tools, expected exactly %d — a write tool must not appear in the read-only set", len(res.Tools), len(want))
	}
}

// The environment projection is a security boundary: TLSEnvironment carries
// enrollment secrets and certificates that must not reach a model context.
func TestListEnvironmentsOmitsSecrets(t *testing.T) {
	s := connect(t, newFake())
	var out listEnvironmentsOut
	res := call(t, s, "list_environments", nil, &out)

	if len(out.Environments) != 1 || out.Environments[0].Name != "dev" {
		t.Fatalf("unexpected environments: %+v", out.Environments)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"SUPERSECRET", "BEGIN CERTIFICATE", "secret", "certificate"} {
		if containsFold(string(raw), leak) {
			t.Errorf("environment payload leaked %q: %s", leak, raw)
		}
	}
}

func TestSearchNodesFiltersAndCaps(t *testing.T) {
	s := connect(t, newFake())

	var all searchNodesOut
	call(t, s, "search_nodes", map[string]any{"environment": "dev"}, &all)
	if all.Matched != 3 || all.Returned != 3 || all.Truncated {
		t.Fatalf("unfiltered search: %+v", all)
	}

	var linux searchNodesOut
	call(t, s, "search_nodes", map[string]any{"environment": "dev", "platform": "linux"}, &linux)
	if linux.Matched != 2 {
		t.Fatalf("platform filter: got %d linux nodes, want 2", linux.Matched)
	}

	var byName searchNodesOut
	call(t, s, "search_nodes", map[string]any{"environment": "dev", "hostname_contains": "WEB"}, &byName)
	if byName.Matched != 2 {
		t.Fatalf("hostname filter should be case-insensitive: got %d, want 2", byName.Matched)
	}

	// Truncation must be reported, or the model reads a capped list as complete.
	var capped searchNodesOut
	call(t, s, "search_nodes", map[string]any{"environment": "dev", "limit": 1}, &capped)
	if capped.Matched != 3 || capped.Returned != 1 || !capped.Truncated {
		t.Fatalf("expected truncated result, got %+v", capped)
	}
}

func TestSearchNodesRejectsBadInput(t *testing.T) {
	s := connect(t, newFake())
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"missing environment", map[string]any{}},
		{"bad status", map[string]any{"environment": "dev", "status": "sideways"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: "search_nodes", Arguments: tc.args})
			if err == nil && !res.IsError {
				t.Fatal("expected an error result")
			}
		})
	}
}

func TestGetNodeWithPosture(t *testing.T) {
	s := connect(t, newFake())

	var plain getNodeOut
	call(t, s, "get_node", map[string]any{"environment": "dev", "identifier": "web-01"}, &plain)
	if plain.Node.UUID != "UUID1" {
		t.Fatalf("resolved wrong node: %+v", plain.Node)
	}
	if plain.Posture != nil {
		t.Error("posture returned without include_posture")
	}

	var withPosture getNodeOut
	call(t, s, "get_node", map[string]any{"environment": "dev", "identifier": "UUID1", "include_posture": true}, &withPosture)
	if withPosture.Posture == nil {
		t.Fatal("include_posture did not return posture")
	}
	if withPosture.Posture.RiskLevel != "medium" {
		t.Errorf("risk level = %q, want medium", withPosture.Posture.RiskLevel)
	}
	// Categories are de-duplicated; the fake returns disk twice.
	if len(withPosture.Posture.Categories) != 2 {
		t.Errorf("categories = %v, want 2 distinct", withPosture.Posture.Categories)
	}
}

func TestSchemaTools(t *testing.T) {
	s := connect(t, newFake())

	var darwin listTablesOut
	call(t, s, "list_osquery_tables", map[string]any{"platform": "darwin"}, &darwin)
	if darwin.Matched != 2 {
		t.Fatalf("darwin tables = %d, want 2", darwin.Matched)
	}

	var filtered listTablesOut
	call(t, s, "list_osquery_tables", map[string]any{"platform": "windows"}, &filtered)
	if filtered.Matched != 1 || filtered.Tables[0].Name != "processes" {
		t.Fatalf("windows tables: %+v", filtered.Tables)
	}

	var schema getTableSchemaOut
	call(t, s, "get_table_schema", map[string]any{"name": "PROCESSES"}, &schema)
	if schema.Name != "processes" || len(schema.Columns) != 2 {
		t.Fatalf("schema lookup should be case-insensitive and carry columns: %+v", schema)
	}

	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "get_table_schema", Arguments: map[string]any{"name": "nope"},
	})
	if err == nil && !res.IsError {
		t.Fatal("unknown table should be an error, not an empty schema")
	}
}

func TestQueryTools(t *testing.T) {
	s := connect(t, newFake())

	var qs listQueriesOut
	call(t, s, "list_queries", map[string]any{"environment": "dev"}, &qs)
	if len(qs.Queries) != 1 || qs.Queries[0].Name != "query_1" {
		t.Fatalf("unexpected queries: %+v", qs.Queries)
	}

	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "list_queries", Arguments: map[string]any{"environment": "dev", "target": "bogus"},
	})
	if err == nil && !res.IsError {
		t.Fatal("invalid target should be rejected")
	}

	var saved listSavedQueriesOut
	call(t, s, "list_saved_queries", map[string]any{"environment": "dev"}, &saved)
	if len(saved.SavedQueries) != 1 {
		t.Fatalf("unexpected saved queries: %+v", saved.SavedQueries)
	}

	var results getQueryResultsOut
	call(t, s, "get_query_results", map[string]any{"environment": "dev", "name": "query_1"}, &results)
	if results.TotalItems != 1 || len(results.Rows) != 1 {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results.PageSize != defaultResultPageSize {
		t.Errorf("page_size = %d, want default %d", results.PageSize, defaultResultPageSize)
	}

	over, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_query_results",
		Arguments: map[string]any{"environment": "dev", "name": "query_1", "page_size": maxResultPageSize + 1},
	})
	if err == nil && !over.IsError {
		t.Fatal("page_size above the maximum should be rejected rather than silently clamped")
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexFold(haystack, needle) >= 0
}

func indexFold(s, substr string) int {
	ls, lsub := len(s), len(substr)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], substr[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
