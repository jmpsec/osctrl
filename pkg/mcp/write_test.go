package mcp

import (
	"context"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
)

// fakeWrites records what the tools asked osctrl to do.
type fakeWrites struct {
	ranQuery  string
	ranEnv    string
	uuids     []string
	hosts     []string
	platforms []string
	tagsSel   []string
	hidden    bool
	exp       int

	expired   string
	completed string

	taggedNode string
	taggedTag  string
	taggedType uint
}

func (f *fakeWrites) RunQuery(env, query string, uuids, hosts, platforms, tagsSel []string, hidden bool, exp int) (types.ApiQueriesResponse, error) {
	f.ranEnv, f.ranQuery = env, query
	f.uuids, f.hosts, f.platforms, f.tagsSel = uuids, hosts, platforms, tagsSel
	f.hidden, f.exp = hidden, exp
	return types.ApiQueriesResponse{Name: "query_abc"}, nil
}

func (f *fakeWrites) ExpireQuery(env, name string) (types.ApiGenericResponse, error) {
	f.expired = name
	return types.ApiGenericResponse{Message: "expired"}, nil
}

func (f *fakeWrites) CompleteQuery(env, name string) (types.ApiGenericResponse, error) {
	f.completed = name
	return types.ApiGenericResponse{Message: "completed"}, nil
}

func (f *fakeWrites) TagNode(env, identifier, tag string, tagType uint, custom string) error {
	f.taggedNode, f.taggedTag, f.taggedType = identifier, tag, tagType
	return nil
}

func connectWithWrites(t *testing.T, b Backend, w WriteBackend) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := sdk.NewInMemoryTransports()
	srv := NewServer(b, "test", WithWrites(w))
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

func toolNames(t *testing.T, s *sdk.ClientSession) map[string]bool {
	t.Helper()
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	out := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		out[tool.Name] = true
	}
	return out
}

var writeTools = []string{"run_query", "expire_query", "complete_query", "tag_node"}

// The whole safety model is that writes are opt-in by construction. If this
// ever fails, a read-only deployment is handing an agent the fleet.
func TestWriteToolsAbsentWithoutOptIn(t *testing.T) {
	got := toolNames(t, connect(t, newFake()))
	for _, name := range writeTools {
		if got[name] {
			t.Errorf("write tool %s registered on a read-only server", name)
		}
	}
}

func TestWriteToolsPresentWithOptIn(t *testing.T) {
	got := toolNames(t, connectWithWrites(t, newFake(), &fakeWrites{}))
	for _, name := range writeTools {
		if !got[name] {
			t.Errorf("write tool %s missing after WithWrites", name)
		}
	}
	// Reads must still be there.
	if !got["search_nodes"] {
		t.Error("read tools disappeared when writes were enabled")
	}
}

func TestRunQueryRequiresExplicitTarget(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)

	// osctrl reads "no selectors" as the whole environment. An omitted
	// argument must not become a fleet-wide query.
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "run_query",
		Arguments: map[string]any{"environment": "dev", "query": "select * from uptime"},
	})
	if err == nil && !res.IsError {
		t.Fatal("a query with no target must be refused")
	}
	if w.ranQuery != "" {
		t.Fatal("query was scheduled despite having no target")
	}

	// all_nodes is the deliberate way to say it.
	var out runQueryOut
	call(t, s, "run_query", map[string]any{
		"environment": "dev", "query": "select * from uptime", "all_nodes": true,
	}, &out)
	if out.Name != "query_abc" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestRunQueryRejectsContradictoryTargets(t *testing.T) {
	s := connectWithWrites(t, newFake(), &fakeWrites{})
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "run_query",
		Arguments: map[string]any{
			"environment": "dev", "query": "select 1", "all_nodes": true, "platforms": []string{"linux"},
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("all_nodes combined with a specific target must be refused")
	}
}

// osctrl treats ExpHours == 0 as "never expires". An agent-scheduled query
// must never be unbounded.
func TestRunQueryAlwaysBoundsExpiration(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)

	call(t, s, "run_query", map[string]any{
		"environment": "dev", "query": "select 1", "platforms": []string{"linux"},
	}, &runQueryOut{})
	if w.exp != defaultQueryExpirationHours {
		t.Errorf("expiration = %d, want the %dh default rather than unbounded", w.exp, defaultQueryExpirationHours)
	}

	w.exp = 0
	call(t, s, "run_query", map[string]any{
		"environment": "dev", "query": "select 1", "platforms": []string{"linux"}, "expiration_hours": 0,
	}, &runQueryOut{})
	if w.exp != defaultQueryExpirationHours {
		t.Errorf("explicit 0 became %d, want the %dh default — 0 means never-expires in osctrl", w.exp, defaultQueryExpirationHours)
	}

	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "run_query",
		Arguments: map[string]any{
			"environment": "dev", "query": "select 1", "platforms": []string{"linux"},
			"expiration_hours": maxQueryExpirationHours + 1,
		},
	})
	if err == nil && !res.IsError {
		t.Error("expiration above the maximum must be refused, not silently clamped")
	}
}

// Carves copy files off endpoints. Not a capability this server offers.
func TestRunQueryRefusesCarves(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "run_query",
		Arguments: map[string]any{
			"environment": "dev", "query": "SELECT * FROM carves WHERE path = '/etc/passwd' AND carve = 1",
			"all_nodes": true,
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("carve query must be refused")
	}
	if w.ranQuery != "" {
		t.Fatal("carve query was scheduled")
	}
}

// Operators must be able to see what an agent scheduled.
func TestRunQueryIsNeverHidden(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)
	call(t, s, "run_query", map[string]any{
		"environment": "dev", "query": "select 1", "uuids": []string{"UUID1"},
	}, &runQueryOut{})
	if w.hidden {
		t.Error("query scheduled as hidden — agent activity must be visible in the UI")
	}
	if len(w.uuids) != 1 || w.uuids[0] != "UUID1" {
		t.Errorf("targets not forwarded: %+v", w.uuids)
	}
}

func TestQueryLifecycleTools(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)

	var out queryActionOut
	call(t, s, "expire_query", map[string]any{"environment": "dev", "name": "query_1"}, &out)
	if w.expired != "query_1" || out.Message != "expired" {
		t.Fatalf("expire: %+v / %s", out, w.expired)
	}
	call(t, s, "complete_query", map[string]any{"environment": "dev", "name": "query_2"}, &out)
	if w.completed != "query_2" {
		t.Fatalf("complete: %s", w.completed)
	}

	for _, args := range []map[string]any{
		{"name": "query_1"},
		{"environment": "dev"},
	} {
		res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: "expire_query", Arguments: args})
		if err == nil && !res.IsError {
			t.Errorf("expire_query accepted incomplete args %+v", args)
		}
	}
}

func TestTagNodeUsesCustomTagType(t *testing.T) {
	w := &fakeWrites{}
	s := connectWithWrites(t, newFake(), w)

	var out tagNodeOut
	call(t, s, "tag_node", map[string]any{"environment": "dev", "identifier": "UUID1", "tag": "quarantine"}, &out)
	if w.taggedNode != "UUID1" || w.taggedTag != "quarantine" {
		t.Fatalf("tag not applied: %+v", w)
	}
	// Environment and platform tags are osctrl's own derived tags and must
	// not be forgeable from here.
	if w.taggedType != tags.TagTypeCustom {
		t.Errorf("tag type = %d, want TagTypeCustom (%d)", w.taggedType, tags.TagTypeCustom)
	}

	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "tag_node", Arguments: map[string]any{"environment": "dev", "identifier": "UUID1"},
	})
	if err == nil && !res.IsError {
		t.Error("tag_node without a tag must be refused")
	}
}

// The model should only be told about writes when it actually has them.
func TestInstructionsMentionWritesOnlyWhenEnabled(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{"read-only", nil, false},
		{"with writes", []Option{WithWrites(&fakeWrites{})}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverT, clientT := sdk.NewInMemoryTransports()
			srv := NewServer(newFake(), "test", tc.opts...)
			if _, err := srv.Connect(ctx, serverT, nil); err != nil {
				t.Fatalf("server connect: %v", err)
			}
			client := sdk.NewClient(&sdk.Implementation{Name: "c", Version: "t"}, nil)
			session, err := client.Connect(ctx, clientT, nil)
			if err != nil {
				t.Fatalf("client connect: %v", err)
			}
			defer func() { _ = session.Close() }()

			instructions := session.InitializeResult().Instructions
			got := indexFold(instructions, "write tools") >= 0
			if got != tc.want {
				t.Errorf("instructions mention writes = %v, want %v", got, tc.want)
			}
		})
	}
}
