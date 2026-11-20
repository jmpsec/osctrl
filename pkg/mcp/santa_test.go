package mcp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/santa"
)

var santaSHA = strings.Repeat("ab", 32)

// santaCalls records what the Santa tools asked the backend for. It is
// shared by pointer because the tools get the backend by interface.
type santaCalls struct {
	filter         santa.EventFilter
	page, pageSize int
	machineID      string
	manyRules      int
	created        *santa.RuleSpec
	deleted        uint
	days           int
	mode           *apiclient.SantaModeInput
	modeHeld       bool
	modeDeleted    uint
}

var santaLast = &santaCalls{}

func (f *fakeBackend) GetSantaRules(env string) ([]santa.Rule, error) {
	if santaLast.manyRules > 0 {
		out := make([]santa.Rule, santaLast.manyRules)
		for i := range out {
			out[i] = santa.Rule{ID: uint(i + 1), RuleType: "TEAMID", Identifier: fmt.Sprintf("TEAM%06d", i), Policy: "ALLOWLIST", Scope: "env"}
		}
		return out, f.err
	}
	return []santa.Rule{
		{ID: 1, RuleType: "BINARY", Identifier: santaSHA, Policy: "BLOCKLIST", Scope: "env", CustomURL: "https://example.com/why"},
		{ID: 2, RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "pilot"},
	}, f.err
}

func (f *fakeBackend) GetSantaMachines(env string) ([]santa.Machine, error) {
	now := time.Now()
	return []santa.Machine{
		{MachineID: "M-1", Hostname: "mac-01", AssignedMode: "LOCKDOWN", ModeSource: "tag", AppliedDigest: "d1", PendingDigest: "d1", LastSyncAt: &now},
		{MachineID: "M-2", Hostname: "mac-02", AssignedMode: "MONITOR", ModeSource: "env", AppliedDigest: "d1", PendingDigest: "d2"},
	}, f.err
}

func (f *fakeBackend) GetSantaEvents(env string, filter santa.EventFilter, page, pageSize int) (apiclient.SantaEvents, error) {
	santaLast.filter, santaLast.page, santaLast.pageSize = filter, page, pageSize
	return apiclient.SantaEvents{Total: 7, Page: page, Events: []santa.Event{
		{ID: 9, EnvironmentID: 3, NodeID: 4, MachineID: "M-1", Decision: "BLOCK_BINARY", FilePath: "/tmp", FileName: "evil", FileSHA256: santaSHA},
	}}, f.err
}

func (f *fakeBackend) GetSantaEffectiveRules(env, machineID string) (apiclient.SantaEffectiveRules, error) {
	santaLast.machineID = machineID
	return apiclient.SantaEffectiveRules{ClientMode: "LOCKDOWN", ModeSource: "tag", Rules: []santa.Rule{
		{ID: 2, RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "pilot"},
	}}, f.err
}

func (f *fakeBackend) GetSantaConfig(env string) (apiclient.SantaConfig, error) {
	return apiclient.SantaConfig{EnvConfig: santa.EnvConfig{ClientMode: "LOCKDOWN", TokenHash: "secret-hash", RequireSecondAdmin: true}, TokenSet: true}, f.err
}

func (f *fakeBackend) GetSantaModeOverrides(env string) ([]santa.ModeOverride, error) {
	return []santa.ModeOverride{{ID: 4, Scope: "tag", ScopeValue: "pilot", ClientMode: "LOCKDOWN", CreatedBy: "alice"}}, f.err
}

func (f *fakeBackend) GetSantaReport(env string, days int) (santa.Report, error) {
	santaLast.days = days
	return santa.Report{Days: 14, TopBlocked: []santa.RankedBinary{{SHA256: santaSHA, FileName: "evil", Events: 3, Machines: 2}}}, f.err
}

func (f *fakeBackend) GetSantaFileAccessEvents(env, machineID string, page, pageSize int) (apiclient.SantaFileAccessEvents, error) {
	santaLast.machineID, santaLast.page, santaLast.pageSize = machineID, page, pageSize
	return apiclient.SantaFileAccessEvents{Total: 1, Page: page, Events: []santa.FileAccessEvent{
		{ID: 3, MachineID: "M-1", RuleName: "ssh keys", Target: "/Users/a/.ssh/id_ed25519", Decision: "DENIED",
			ProcessChain: []santa.Process{{Pid: 7, FilePath: "/tmp/evil"}}},
	}}, f.err
}

func (f *fakeBackend) GetSantaBinary(env, sha256 string) (santa.Binary, error) {
	return santa.Binary{SHA256: sha256, FileName: "evil", Events: 3, Blocked: 3,
		Risk: &santa.Risk{Verdict: "flagged", Checks: []santa.Verdict{{CheckName: "virustotal", Verdict: "flagged", Detail: "12/70"}}}}, f.err
}

func (f *fakeWrites) SetSantaModeOverride(env string, in apiclient.SantaModeInput) (apiclient.SantaModeResult, error) {
	santaLast.mode = &in
	if santaLast.modeHeld {
		return apiclient.SantaModeResult{Message: "Change 5 needs approval by another admin of this environment; apply it once approved"}, nil
	}
	return apiclient.SantaModeResult{ModeOverride: santa.ModeOverride{ID: 8, Scope: in.Scope, ScopeValue: in.ScopeValue, ClientMode: in.ClientMode}}, nil
}

func (f *fakeWrites) DeleteSantaModeOverride(env string, id uint) error {
	santaLast.modeDeleted = id
	return nil
}

func (f *fakeWrites) CreateSantaRule(env string, spec santa.RuleSpec) (santa.Rule, error) {
	santaLast.created = &spec
	return santa.Rule{ID: 42, RuleType: spec.RuleType, Identifier: spec.Identifier, Policy: spec.Policy, Scope: spec.Scope, ScopeValue: spec.ScopeValue}, nil
}

func (f *fakeWrites) DeleteSantaRule(env string, id uint) error {
	santaLast.deleted = id
	return nil
}

// callFails runs a tool that must be refused and returns the refusal text.
func callFails(t *testing.T, s *sdk.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err.Error()
	}
	if !res.IsError {
		t.Fatalf("%s(%v) succeeded, expected a tool error", name, args)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			text += tc.Text
		}
	}
	return text
}

func TestListSantaRulesFiltersAndCaps(t *testing.T) {
	santaLast = &santaCalls{}
	s := connect(t, newFake())
	tests := []struct {
		name string
		args map[string]any
		ids  []uint
	}{
		{"all", map[string]any{"environment": "dev"}, []uint{1, 2}},
		{"by type", map[string]any{"environment": "dev", "rule_type": "teamid"}, []uint{2}},
		{"by policy", map[string]any{"environment": "dev", "policy": "BLOCKLIST"}, []uint{1}},
		{"by identifier", map[string]any{"environment": "dev", "identifier_contains": "eqhx"}, []uint{2}},
		{"no match", map[string]any{"environment": "dev", "rule_type": "CDHASH"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out listSantaRulesOut
			call(t, s, "list_santa_rules", tt.args, &out)
			var ids []uint
			for _, r := range out.Rules {
				ids = append(ids, r.ID)
			}
			if fmt.Sprint(ids) != fmt.Sprint(tt.ids) || out.Matched != len(tt.ids) || out.Truncated {
				t.Fatalf("got ids %v matched %d truncated %v, want %v", ids, out.Matched, out.Truncated, tt.ids)
			}
		})
	}

	santaLast.manyRules = 700
	var out listSantaRulesOut
	call(t, s, "list_santa_rules", map[string]any{"environment": "dev"}, &out)
	if out.Matched != 700 || out.Returned != defaultSantaLimit || !out.Truncated {
		t.Fatalf("default cap not applied: %+v", out)
	}
	call(t, s, "list_santa_rules", map[string]any{"environment": "dev", "limit": 100000}, &out)
	if out.Returned != maxSantaLimit || !out.Truncated {
		t.Fatalf("maximum cap not applied: returned %d", out.Returned)
	}
	callFails(t, s, "list_santa_rules", map[string]any{"environment": " "})
}

func TestListSantaMachines(t *testing.T) {
	s := connect(t, newFake())
	var out listSantaMachinesOut
	call(t, s, "list_santa_machines", map[string]any{"environment": "dev"}, &out)
	if len(out.Machines) != 2 || !out.Machines[0].RulesInSync || out.Machines[1].RulesInSync {
		t.Fatalf("machines or rules_in_sync wrong: %+v", out.Machines)
	}
	call(t, s, "list_santa_machines", map[string]any{"environment": "dev", "hostname_contains": "MAC-02"}, &out)
	if out.Matched != 1 || out.Machines[0].MachineID != "M-2" {
		t.Fatalf("hostname filter wrong: %+v", out)
	}
}

func TestListSantaEventsPassesFiltersAndBoundsPages(t *testing.T) {
	santaLast = &santaCalls{}
	s := connect(t, newFake())
	var out listSantaEventsOut
	res := call(t, s, "list_santa_events", map[string]any{
		"environment": "dev", "machine_id": " M-1 ", "decision": "BLOCK", "sha256": santaSHA, "page": 2,
	}, &out)
	want := santa.EventFilter{MachineID: "M-1", Decision: "BLOCK", SHA256: santaSHA}
	if santaLast.filter != want || santaLast.page != 2 || santaLast.pageSize != defaultSantaEventPage {
		t.Fatalf("backend got filter %+v page %d size %d", santaLast.filter, santaLast.page, santaLast.pageSize)
	}
	if out.Total != 7 || out.Returned != 1 || out.Events[0].Decision != "BLOCK_BINARY" {
		t.Fatalf("events lost: %+v", out)
	}
	// Internal ids are not part of the projection.
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok && (strings.Contains(tc.Text, "environment_id") || strings.Contains(tc.Text, "node_id")) {
			t.Fatalf("internal ids leaked: %s", tc.Text)
		}
	}

	call(t, s, "list_santa_events", map[string]any{"environment": "dev"}, &out)
	if santaLast.page != 1 {
		t.Fatalf("page defaulted to %d, want 1", santaLast.page)
	}
	if msg := callFails(t, s, "list_santa_events", map[string]any{"environment": "dev", "page_size": maxSantaEventPage + 1}); !strings.Contains(msg, "exceeds the maximum") {
		t.Fatalf("oversized page not refused clearly: %q", msg)
	}
}

func TestGetSantaNodeRules(t *testing.T) {
	santaLast = &santaCalls{}
	s := connect(t, newFake())
	var out santaNodeRulesOut
	call(t, s, "get_santa_node_rules", map[string]any{"environment": "dev", "machine_id": "M-1"}, &out)
	if santaLast.machineID != "M-1" || out.ClientMode != "LOCKDOWN" || out.ModeSource != "tag" || len(out.Rules) != 1 {
		t.Fatalf("effective rules wrong: %+v (asked for %q)", out, santaLast.machineID)
	}
	callFails(t, s, "get_santa_node_rules", map[string]any{"environment": "dev", "machine_id": ""})
}

// A backend error (403, or 503 when Santa is off) must reach the model as a
// tool error, not as an empty list that reads like "no rules".
func TestSantaToolsSurfaceBackendErrors(t *testing.T) {
	b := newFake()
	b.err = fmt.Errorf("error api request - HTTP Code 503 - santa not enabled")
	s := connect(t, b)
	for _, tool := range []string{"list_santa_rules", "list_santa_machines", "list_santa_events"} {
		if msg := callFails(t, s, tool, map[string]any{"environment": "dev"}); !strings.Contains(msg, "santa not enabled") {
			t.Errorf("%s: backend error lost: %q", tool, msg)
		}
	}
}

func TestCreateSantaRule(t *testing.T) {
	santaLast = &santaCalls{}
	s := connectWithWrites(t, newFake(), &fakeWrites{})
	base := map[string]any{"environment": "dev", "rule_type": "TEAMID", "identifier": "EQHXZ8M8AV", "policy": "ALLOWLIST"}
	with := func(k string, v any) map[string]any {
		out := map[string]any{k: v}
		for bk, bv := range base {
			if _, ok := out[bk]; !ok {
				out[bk] = bv
			}
		}
		return out
	}

	// The schema refuses an omitted scope; the tool refuses a blank one.
	callFails(t, s, "create_santa_rule", base)
	if msg := callFails(t, s, "create_santa_rule", with("scope", " ")); !strings.Contains(msg, "scope is required") {
		t.Fatalf("blank scope not refused clearly: %q", msg)
	}
	cel := with("policy", "cel")
	cel["scope"] = "env"
	if msg := callFails(t, s, "create_santa_rule", cel); !strings.Contains(msg, "CEL rules are not available") {
		t.Fatalf("CEL rule not refused: %q", msg)
	}
	if santaLast.created != nil {
		t.Fatal("a refused rule reached the backend")
	}

	args := with("scope", "TAG")
	args["scope_value"] = "pilot"
	var out createSantaRuleOut
	call(t, s, "create_santa_rule", args, &out)
	want := santa.RuleSpec{RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "pilot"}
	if santaLast.created == nil || *santaLast.created != want {
		t.Fatalf("backend got %+v, want %+v", santaLast.created, want)
	}
	if out.Rule.ID != 42 || !strings.Contains(out.Guidance, "42") {
		t.Fatalf("created rule not reported: %+v", out)
	}
}

func TestDeleteSantaRule(t *testing.T) {
	santaLast = &santaCalls{}
	s := connectWithWrites(t, newFake(), &fakeWrites{})
	callFails(t, s, "delete_santa_rule", map[string]any{"environment": "dev", "id": 0})
	if santaLast.deleted != 0 {
		t.Fatal("a refused delete reached the backend")
	}
	call(t, s, "delete_santa_rule", map[string]any{"environment": "dev", "id": 7}, nil)
	if santaLast.deleted != 7 {
		t.Fatalf("deleted %d, want 7", santaLast.deleted)
	}
}

func TestSantaToolsHiddenWithoutSanta(t *testing.T) {
	ctx := context.Background()
	serverT, clientT := sdk.NewInMemoryTransports()
	srv := NewServer(newFake(), "test", WithWrites(&fakeWrites{}), WithoutSanta())
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	for name := range toolNames(t, session) {
		if strings.Contains(name, "santa") {
			t.Errorf("Santa tool %s registered with WithoutSanta", name)
		}
	}
	if strings.Contains(session.InitializeResult().Instructions, "Santa") {
		t.Error("instructions mention Santa with WithoutSanta")
	}
	if !toolNames(t, session)["run_query"] {
		t.Error("other write tools disappeared with WithoutSanta")
	}
}

func TestSantaReadTools(t *testing.T) {
	santaLast = &santaCalls{}
	s := connect(t, newFake())

	var cfg santaConfigOut
	res := call(t, s, "get_santa_config", map[string]any{"environment": "dev"}, &cfg)
	if cfg.Config.ClientMode != "LOCKDOWN" || !cfg.TokenSet || !cfg.Config.RequireSecondAdmin {
		t.Fatalf("config = %+v", cfg)
	}
	if strings.Contains(fmt.Sprint(res.StructuredContent), "secret-hash") {
		t.Fatal("the token hash reached the model")
	}

	var modes santaModesOut
	call(t, s, "list_santa_mode_overrides", map[string]any{"environment": "dev"}, &modes)
	if len(modes.Overrides) != 1 || modes.Overrides[0].ScopeValue != "pilot" {
		t.Fatalf("overrides = %+v", modes.Overrides)
	}

	var rep santa.Report
	call(t, s, "get_santa_report", map[string]any{"environment": "dev", "days": 7}, &rep)
	if santaLast.days != 7 || len(rep.TopBlocked) != 1 {
		t.Fatalf("days %d, report %+v", santaLast.days, rep)
	}
	if msg := callFails(t, s, "get_santa_report", map[string]any{"environment": "dev", "days": 31}); !strings.Contains(msg, "days") {
		t.Fatalf("days 31: %s", msg)
	}

	var fa santaFileAccessOut
	call(t, s, "list_santa_file_access_events", map[string]any{"environment": "dev", "machine_id": " M-1 "}, &fa)
	if santaLast.machineID != "M-1" || santaLast.page != 1 || santaLast.pageSize != defaultSantaEventPage || fa.Returned != 1 || fa.Total != 1 {
		t.Fatalf("calls %+v, out %+v", santaLast, fa)
	}
	if msg := callFails(t, s, "list_santa_file_access_events", map[string]any{"environment": "dev", "page_size": 500}); !strings.Contains(msg, "page_size") {
		t.Fatalf("page_size 500: %s", msg)
	}

	var bin santa.Binary
	call(t, s, "get_santa_binary", map[string]any{"environment": "dev", "sha256": strings.ToUpper(santaSHA)}, &bin)
	if bin.SHA256 != santaSHA || bin.Risk == nil || bin.Risk.Verdict != "flagged" {
		t.Fatalf("binary = %+v", bin)
	}
	if msg := callFails(t, s, "get_santa_binary", map[string]any{"environment": "dev"}); !strings.Contains(msg, "sha256") {
		t.Fatalf("no sha256: %s", msg)
	}
	if msg := callFails(t, s, "get_santa_config", map[string]any{}); !strings.Contains(msg, "environment") {
		t.Fatalf("no environment: %s", msg)
	}
}

func TestSantaModeWriteTools(t *testing.T) {
	santaLast = &santaCalls{}
	s := connectWithWrites(t, newFake(), &fakeWrites{})

	var out setSantaModeOut
	call(t, s, "set_santa_mode_override", map[string]any{
		"environment": "dev", "scope": "Node", "scope_value": " M-1 ", "client_mode": "monitor", "hours": 2,
	}, &out)
	want := apiclient.SantaModeInput{Scope: "node", ScopeValue: "M-1", ClientMode: "MONITOR", Hours: 2}
	if santaLast.mode == nil || *santaLast.mode != want {
		t.Fatalf("sent %+v, want %+v", santaLast.mode, want)
	}
	if out.Override == nil || out.Override.ID != 8 || !strings.Contains(out.Guidance, "Override 8 set") {
		t.Fatalf("out = %+v", out)
	}

	// Held for a second admin: nothing applied, and the model is told so.
	santaLast.modeHeld = true
	out = setSantaModeOut{}
	call(t, s, "set_santa_mode_override", map[string]any{"environment": "dev", "scope": "tag", "scope_value": "pilot", "client_mode": "MONITOR"}, &out)
	if out.Override != nil || !strings.Contains(out.Guidance, "Not applied yet") {
		t.Fatalf("held out = %+v", out)
	}

	var del deleteSantaRuleOut
	call(t, s, "delete_santa_mode_override", map[string]any{"environment": "dev", "id": 4}, &del)
	if santaLast.modeDeleted != 4 {
		t.Fatalf("deleted %d", santaLast.modeDeleted)
	}
	if msg := callFails(t, s, "delete_santa_mode_override", map[string]any{"environment": "dev", "id": 0}); !strings.Contains(msg, "id is required") {
		t.Fatalf("no id: %s", msg)
	}
}
