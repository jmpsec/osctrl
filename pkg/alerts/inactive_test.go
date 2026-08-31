package alerts

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeNodeSource serves scripted snapshots per sweep.
type fakeNodeSource struct {
	mu       sync.Mutex
	inactive []NodeSnapshot
	active   []NodeSnapshot
	inactErr error
	actErr   error
}

func (s *fakeNodeSource) InactiveNodes(_ context.Context) ([]NodeSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inactive, s.inactErr
}

func (s *fakeNodeSource) ActiveNodes(_ context.Context) ([]NodeSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.actErr
}

func (s *fakeNodeSource) setInactive(nodes ...NodeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inactive = nodes
}

func (s *fakeNodeSource) setActive(nodes ...NodeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = nodes
}

// memInactiveState is an in-memory inactiveState for deterministic
// transition tests.
type memInactiveState struct {
	mu   sync.Mutex
	set  map[string]bool
	fail bool
}

func (s *memInactiveState) load(_ context.Context) (map[string]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, fmt.Errorf("state down")
	}
	out := make(map[string]bool, len(s.set))
	for k, v := range s.set {
		out[k] = v
	}
	return out, nil
}

func (s *memInactiveState) save(_ context.Context, inactive map[string]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return fmt.Errorf("state down")
	}
	s.set = make(map[string]bool, len(inactive))
	for k := range inactive {
		s.set[k] = true
	}
	return nil
}

func nodeStateRules(t *testing.T) (*Store, *Worker, *recordingSinkRef) {
	t.Helper()
	rs := &RuleSet{}
	for _, r := range []AlertRule{
		{Model: ruleWithID(1), Name: "offline", Source: SourceNodeInactive, Enabled: true, ChannelIDs: "[1]"},
		{Model: ruleWithID(2), Name: "back", Source: SourceNodeRecovered, Enabled: true, ChannelIDs: "[1]"},
	} {
		cr, err := CompileRule(r)
		if err != nil {
			t.Fatalf("compile %q: %v", r.Name, err)
		}
		switch r.Source {
		case SourceNodeInactive:
			rs.nodeInactive = append(rs.nodeInactive, cr)
		case SourceNodeRecovered:
			rs.nodeRecovered = append(rs.nodeRecovered, cr)
		}
	}
	store := NewStore()
	store.Publish(rs)
	sink := &recordingSinkRef{}
	worker := NewSyncWorker(store, nil, nil, sink)
	return store, worker, sink
}

// recordingSinkRef is a simple recording DispatchSink.
type recordingSinkRef struct {
	mu   sync.Mutex
	hits []Hit
}

func (s *recordingSinkRef) Dispatch(_ context.Context, h Hit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, h)
	return nil
}

func (s *recordingSinkRef) snapshot() []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Hit(nil), s.hits...)
}

func (s *recordingSinkRef) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = nil
}

// TestInactiveWatcherNoRulesNoQueries: with no node-state rules the
// sweep must not produce hits (it also skips the source queries —
// observable because the fake source returns nothing and nothing is
// enqueued).
func TestInactiveWatcherNoRulesNoQueries(t *testing.T) {
	source := &fakeNodeSource{}
	store, worker, sink := nodeStateRules(t)
	store.Publish(&RuleSet{}) // empty the snapshot
	w := newInactiveWatcherWithState(source, store, worker, &memInactiveState{})
	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 {
		t.Fatalf("no rules must yield no hits: %+v", sink.snapshot())
	}
}

// TestInactiveWatcherFireOncePerTransition covers the full lifecycle:
// inactive fires once, an unchanged second sweep is silent, recovery
// fires once, and a re-inactive transition fires again.
func TestInactiveWatcherFireOncePerTransition(t *testing.T) {
	source := &fakeNodeSource{}
	store, worker, sink := nodeStateRules(t)
	state := &memInactiveState{}
	w := newInactiveWatcherWithState(source, store, worker, state)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }

	stale := now.Add(-96 * time.Hour)
	source.setInactive(NodeSnapshot{UUID: "U-1", EnvironmentID: 7, Environment: "prod", Hostname: "host-1", Active: false, LastSeen: stale})

	// Sweep 1: transition fires.
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 {
		t.Fatalf("expected 1 inactive hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.RuleName != "offline" || h.NodeUUID != "U-1" || h.Environment != "prod" {
		t.Fatalf("unexpected hit: %+v", h)
	}
	if h.Entity != "U-1" {
		t.Fatalf("entity should be the uuid: %q", h.Entity)
	}
	if h.Detail == "" {
		t.Fatal("detail should describe the staleness")
	}

	// Sweep 2: unchanged state is silent.
	sink.reset()
	w.Sweep(context.Background())
	if hits := sink.snapshot(); len(hits) != 0 {
		t.Fatalf("unchanged sweep must not re-fire: %+v", hits)
	}

	// Sweep 3: node recovers.
	source.setInactive()
	source.setActive(NodeSnapshot{UUID: "U-1", EnvironmentID: 7, Environment: "prod", Hostname: "host-1", Active: true, LastSeen: now})
	sink.reset()
	w.Sweep(context.Background())
	hits = sink.snapshot()
	if len(hits) != 1 || hits[0].RuleName != "back" {
		t.Fatalf("expected 1 recovered hit, got %+v", hits)
	}

	// Sweep 4: recovery is not repeated.
	sink.reset()
	w.Sweep(context.Background())
	if hits := sink.snapshot(); len(hits) != 0 {
		t.Fatalf("recovered node must not re-fire: %+v", hits)
	}

	// Sweep 5: node goes inactive again → fires again.
	source.setInactive(NodeSnapshot{UUID: "U-1", EnvironmentID: 7, Environment: "prod", Hostname: "host-1", LastSeen: stale})
	source.setActive()
	sink.reset()
	w.Sweep(context.Background())
	if hits := sink.snapshot(); len(hits) != 1 || hits[0].RuleName != "offline" {
		t.Fatalf("re-inactive transition must fire again, got %+v", hits)
	}
}

// TestInactiveWatcherEnvScoping: a node_inactive rule scoped to env 7
// must not fire for nodes in other environments.
func TestInactiveWatcherEnvScoping(t *testing.T) {
	rs := &RuleSet{}
	cr, err := CompileRule(AlertRule{Model: ruleWithID(9), Name: "prod-only", EnvironmentID: 7, Source: SourceNodeInactive})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs.nodeInactive = append(rs.nodeInactive, cr)
	store := NewStore()
	store.Publish(rs)
	sink := &recordingSinkRef{}
	worker := NewSyncWorker(store, nil, nil, sink)
	source := &fakeNodeSource{}
	w := newInactiveWatcherWithState(source, store, worker, &memInactiveState{})

	source.setInactive(
		NodeSnapshot{UUID: "U-PROD", EnvironmentID: 7, Environment: "prod", Hostname: "h1"},
		NodeSnapshot{UUID: "U-DEV", EnvironmentID: 9, Environment: "dev", Hostname: "h2"},
	)
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || hits[0].NodeUUID != "U-PROD" {
		t.Fatalf("env-scoped rule must only hit prod node: %+v", hits)
	}
}

// TestInactiveWatcherSourceErrors: a failing source logs and no-ops.
func TestInactiveWatcherSourceErrors(t *testing.T) {
	source := &fakeNodeSource{inactErr: fmt.Errorf("db down")}
	store, worker, sink := nodeStateRules(t)
	w := newInactiveWatcherWithState(source, store, worker, &memInactiveState{})
	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 {
		t.Fatalf("source error must yield no hits: %+v", sink.snapshot())
	}
}

// TestInactiveWatcherLiveRedis asserts the once-per-transition
// guarantee against a real Redis (state set persistence).
func TestInactiveWatcherLiveRedis(t *testing.T) {
	client, ok := liveRedis(t)
	if !ok {
		t.Skip("REDIS_URL not set; live watcher test skipped")
	}
	ctx := context.Background()
	_ = client.Del(ctx, inactiveStateKey()).Err()

	source := &fakeNodeSource{}
	store, worker, sink := nodeStateRules(t)
	w := NewInactiveWatcher(source, store, worker, client)

	stale := time.Now().Add(-96 * time.Hour)
	source.setInactive(NodeSnapshot{UUID: "WATCH-U1", EnvironmentID: 0, Environment: "prod", Hostname: "host", LastSeen: stale})

	// First sweep fires; second sweep with the same state must not.
	w.Sweep(ctx)
	if got := len(sink.snapshot()); got != 1 {
		t.Fatalf("first sweep should fire once, got %d", got)
	}
	sink.reset()
	w.Sweep(ctx)
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("second sweep with unchanged state must not re-fire, got %d", got)
	}

	// Recovery: node leaves the inactive set and reappears active.
	source.setInactive()
	source.setActive(NodeSnapshot{UUID: "WATCH-U1", EnvironmentID: 0, Environment: "prod", Hostname: "host", Active: true})
	sink.reset()
	w.Sweep(ctx)
	hits := sink.snapshot()
	if len(hits) != 1 || hits[0].RuleName != "back" {
		t.Fatalf("expected one recovery hit, got %+v", hits)
	}
	// And a subsequent inactive transition fires again.
	sink.reset()
	source.setInactive(NodeSnapshot{UUID: "WATCH-U1", EnvironmentID: 0, Environment: "prod", Hostname: "host", LastSeen: stale})
	source.setActive()
	w.Sweep(ctx)
	if len(sink.snapshot()) != 1 {
		t.Fatalf("re-inactive transition must fire again, got %+v", sink.snapshot())
	}
	_ = client.Del(ctx, inactiveStateKey()).Err()
}

// TestHumanSince pins the coarse rendering used in hit details.
func TestHumanSince(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		last time.Time
		want string
	}{
		{now.Add(-30 * time.Minute), "30m ago"},
		{now.Add(-5 * time.Hour), "5h ago"},
		{now.Add(-96 * time.Hour), "4d ago"},
		{time.Time{}, "never"},
	}
	for _, c := range cases {
		if got := humanSince(now, c.last); got != c.want {
			t.Errorf("humanSince(%v) = %q, want %q", c.last, got, c.want)
		}
	}
}
