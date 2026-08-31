package alerts

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&AlertRule{}, &AlertChannel{}, &AlertHistory{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return &Manager{DB: db}
}

func TestRuleCRUD(t *testing.T) {
	m := newTestManager(t)

	rule := AlertRule{
		Name:            "sudoers-write",
		Source:          SourceResultLog,
		MatchType:       MatchTypeSubstring,
		MatchValue:      "/etc/sudoers",
		CooldownMinutes: 30,
		ChannelIDs:      "[1,2]",
		Enabled:         true,
	}
	created, err := m.CreateRule(rule)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if created.ID == 0 || created.ChannelIDs != "[1,2]" {
		t.Fatalf("unexpected created row: %+v", created)
	}

	// duplicate (name, env) must collide on the unique index
	if _, err := m.CreateRule(rule); !errors.Is(err, ErrRuleExists) {
		t.Fatalf("expected ErrRuleExists, got %v", err)
	}

	// same name, different env is allowed
	ruleEnv2 := rule
	ruleEnv2.EnvironmentID = 7
	if _, err := m.CreateRule(ruleEnv2); err != nil {
		t.Fatalf("CreateRule in second env: %v", err)
	}

	// update
	created.MatchValue = "/etc/sudoers.d"
	updated, err := m.UpdateRule(created.ID, created)
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if updated.MatchValue != "/etc/sudoers.d" {
		t.Fatalf("update not applied: %+v", updated)
	}

	// get / list / delete
	got, err := m.GetRule(created.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if got.Name != "sudoers-write" {
		t.Fatalf("unexpected rule: %+v", got)
	}
	rules, err := m.ListRules(nil)
	if err != nil || len(rules) != 2 {
		t.Fatalf("ListRules: %v %d", err, len(rules))
	}
	env := uint(7)
	scoped, err := m.ListRules(&env)
	if err != nil || len(scoped) != 1 {
		t.Fatalf("ListRules(env): %v %d", err, len(scoped))
	}
	if err := m.DeleteRule(created.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if err := m.DeleteRule(created.ID); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("second delete should 404, got %v", err)
	}
}

func TestRuleCap(t *testing.T) {
	m := newTestManager(t)
	for i := 0; i < MaxRulesPerEnv; i++ {
		if _, err := m.CreateRule(AlertRule{
			Name:       "rule-" + string(rune('a'+i%26)) + time.Duration(i).String(),
			Source:     SourceResultLog,
			MatchType:  MatchTypeSubstring,
			MatchValue: "x",
		}); err != nil {
			t.Fatalf("rule %d rejected: %v", i, err)
		}
	}
	if _, err := m.CreateRule(AlertRule{
		Name:       "overflow",
		Source:     SourceResultLog,
		MatchType:  MatchTypeSubstring,
		MatchValue: "x",
	}); !errors.Is(err, ErrTooManyRules) {
		t.Fatalf("expected ErrTooManyRules, got %v", err)
	}
	// different env is unaffected
	if _, err := m.CreateRule(AlertRule{
		Name:          "overflow-ok",
		EnvironmentID: 9,
		Source:        SourceResultLog,
		MatchType:     MatchTypeSubstring,
		MatchValue:    "x",
	}); err != nil {
		t.Fatalf("rule in other env rejected: %v", err)
	}
}

func TestCreateRuleRejectsInvalid(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.CreateRule(AlertRule{Name: "bad", Source: "nope", MatchType: MatchTypeSubstring, MatchValue: "x"}); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("expected ErrInvalidSource, got %v", err)
	}
	if _, err := m.CreateRule(AlertRule{Name: "bad", Source: SourceResultLog, MatchType: MatchTypeRegex, MatchValue: "("}); err == nil {
		t.Fatal("expected invalid regex rejection")
	}
}

func TestChannelCRUD(t *testing.T) {
	m := newTestManager(t)
	ch, err := m.CreateChannel(AlertChannel{Name: "soc-webhook", Type: "webhook", Config: `{"url":"https://example.com/hook"}`, Enabled: true})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	if _, err := m.CreateChannel(AlertChannel{Name: "soc-webhook", Type: "webhook"}); !errors.Is(err, ErrChannelExists) {
		t.Fatalf("expected ErrChannelExists, got %v", err)
	}
	ch.Info = "updated"
	if _, err := m.UpdateChannel(ch.ID, ch); err != nil {
		t.Fatalf("UpdateChannel: %v", err)
	}
	got, err := m.GetChannel(ch.ID)
	if err != nil || got.Info != "updated" {
		t.Fatalf("GetChannel: %v %+v", err, got)
	}
	if err := m.DeleteChannel(ch.ID); err != nil {
		t.Fatalf("DeleteChannel: %v", err)
	}
	if err := m.DeleteChannel(ch.ID); !errors.Is(err, ErrChannelNotFound) {
		t.Fatalf("expected ErrChannelNotFound, got %v", err)
	}
}

func TestHistory(t *testing.T) {
	m := newTestManager(t)
	if err := m.RecordHistory(AlertHistory{RuleName: "r", Entity: "e", Detail: strings.Repeat("x", 3000)}); err != nil {
		t.Fatalf("RecordHistory: %v", err)
	}
	rows, err := m.RecentHistory(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("RecentHistory: %v %d", err, len(rows))
	}
	if len(rows[0].Detail) > detailMax+16 { // DB may store full; matcher bounds at write time
		t.Fatalf("detail suspiciously long: %d", len(rows[0].Detail))
	}
	n, err := m.PruneHistory(time.Now().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneHistory: %v %d", err, n)
	}
}

func TestLoadSnapshot(t *testing.T) {
	m := newTestManager(t)
	seed := []AlertRule{
		{Name: "r1", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "alpha", Enabled: true},
		{Name: "r2", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "beta", Enabled: true},
		{Name: "r3-disabled", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "gamma", Enabled: false},
		{Name: "r5-node", Source: SourceNodeInactive, Enabled: true},
	}
	for _, s := range seed {
		if _, err := m.CreateRule(s); err != nil {
			t.Fatalf("seed %q: %v", s.Name, err)
		}
	}
	// r4 has an invalid regex introduced by direct DB edit — bypass
	// manager validation to simulate operator-editing rows outside the
	// API. LoadSnapshot must skip it, not fail.
	if err := m.DB.Create(&AlertRule{
		Name: "r4-badregex", Source: SourceResultLog,
		MatchType: MatchTypeRegex, MatchValue: "(", Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seed r4: %v", err)
	}
	store := NewStore()
	if err := m.LoadSnapshot(store); err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	rs := store.Snapshot()
	r, s, q := rs.counts()
	if r != 1 || s != 1 || q != 0 {
		t.Fatalf("expected 1 result + 1 status rule, got %d/%d/%d (disabled and broken rules must be skipped)", r, s, q)
	}
}

// TestStateClaim exercises the Redis gate against a live Redis when
// REDIS_URL is set; otherwise it validates the pure helpers only.
func TestStateClaim(t *testing.T) {
	s := &State{now: time.Now}

	// cooldownWindow resolution
	if w := cooldownWindow(0); w != DefaultCooldown {
		t.Fatalf("default cooldown wrong: %v", w)
	}
	if w := cooldownWindow(30); w != 30*time.Minute {
		t.Fatalf("explicit cooldown wrong: %v", w)
	}

	// claim key stability
	h := Hit{RuleID: 1, Entity: "u:q", Detail: "d"}
	before := claimKey(h)
	if k1, k2 := claimKey(h), claimKey(h); k1 != k2 || k1 != before {
		t.Fatalf("claim key not deterministic: %q vs %q", k1, k2)
	}
	h.Detail = "other"
	if after := claimKey(h); after == before {
		t.Fatalf("different detail must change the claim key: %q", after)
	}

	client, ok := liveRedis(t)
	if !ok {
		t.Skip("REDIS_URL not set; live claim test skipped")
	}
	s.client = client
	ctx := context.Background()
	first, err := s.Claim(ctx, Hit{RuleID: 42, Entity: "node-1:file_events", Detail: "match", CooldownMinutes: 1})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !first {
		t.Fatal("first claim must succeed")
	}
	second, err := s.Claim(ctx, Hit{RuleID: 42, Entity: "node-1:file_events", Detail: "match", CooldownMinutes: 1})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if second {
		t.Fatal("second identical claim within window must collapse")
	}
	// different detail alerts independently
	third, err := s.Claim(ctx, Hit{RuleID: 42, Entity: "node-1:file_events", Detail: "different", CooldownMinutes: 1})
	if err != nil || !third {
		t.Fatalf("different detail must claim: %v", err)
	}
	// release re-opens the window
	s.Release(ctx, Hit{RuleID: 42, Entity: "node-1:file_events", Detail: "match"})
	fourth, err := s.Claim(ctx, Hit{RuleID: 42, Entity: "node-1:file_events", Detail: "match", CooldownMinutes: 1})
	if err != nil || !fourth {
		t.Fatalf("claim after release must succeed: %v", err)
	}
}

func liveRedis(t *testing.T) (*redis.Client, bool) {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, false
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, false
	}
	client := redis.NewClient(opt)
	if err := client.Ping(context.Background()).Err(); err != nil {
		_ = client.Close()
		return nil, false
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, true
}
