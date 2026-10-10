package alerts

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFindingSource struct {
	mu          sync.Mutex
	findings    []FindingSnapshot
	escalations []FindingSnapshot
	calls       int
}

func (s *fakeFindingSource) FindingsAfter(_ context.Context, afterID uint, limit int) ([]FindingSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	sorted := slices.Clone(s.findings)
	slices.SortFunc(sorted, func(a, b FindingSnapshot) int { return cmp.Compare(a.ID, b.ID) })
	var out []FindingSnapshot
	for _, f := range sorted {
		if f.ID > afterID && len(out) < limit {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *fakeFindingSource) LatestFindingID(_ context.Context) (uint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max uint
	for _, f := range s.findings {
		if f.ID > max {
			max = f.ID
		}
	}
	return max, nil
}

func (s *fakeFindingSource) EscalationsAfter(_ context.Context, afterID uint, limit int) ([]FindingSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []FindingSnapshot
	for _, f := range s.escalations {
		if f.ID > afterID && len(out) < limit {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *fakeFindingSource) LatestEscalationID(_ context.Context) (uint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max uint
	for _, f := range s.escalations {
		if f.ID > max {
			max = f.ID
		}
	}
	return max, nil
}

func (s *fakeFindingSource) escalate(fs ...FindingSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.escalations = append(s.escalations, fs...)
}

func (s *fakeFindingSource) add(fs ...FindingSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, fs...)
}

type memCursor struct {
	val   uint
	set   bool
	fail  bool
	saves int
}

func (c *memCursor) load(_ context.Context) (uint, bool, error) {
	if c.fail {
		return 0, false, errors.New("redis down")
	}
	return c.val, c.set, nil
}

func (c *memCursor) save(_ context.Context, v uint) error {
	c.val, c.set = v, true
	c.saves++
	return nil
}

func vulnRules(t *testing.T, rules ...AlertRule) (*Store, *Worker, *recordingSinkRef) {
	t.Helper()
	rs := &RuleSet{}
	for _, r := range rules {
		cr, err := CompileRule(r)
		if err != nil {
			t.Fatalf("compile %q: %v", r.Name, err)
		}
		rs.vulnFinding = append(rs.vulnFinding, cr)
	}
	store := NewStore()
	store.Publish(rs)
	sink := &recordingSinkRef{}
	return store, NewSyncWorker(store, nil, nil, sink), sink
}

func finding(id uint, node, advisory, severity string, kev bool) FindingSnapshot {
	return FindingSnapshot{
		ID: id, NodeUUID: node, Hostname: strings.ToLower(node), EnvironmentID: 1, Environment: "prod",
		AdvisoryID: advisory, Package: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.13-1",
		Severity: severity, KEV: kev,
	}
}

var highRule = AlertRule{Model: ruleWithID(1), Name: "high", Source: SourceVulnFinding, VulnMinSeverity: VulnMinHigh, Enabled: true, ChannelIDs: "[1]"}

// On first enable (or after Redis lost the key) existing findings are
// history, not news: the cursor starts at the newest one.
func TestVulnWatcherFirstSweepStartsAtNow(t *testing.T) {
	source := &fakeFindingSource{}
	source.add(finding(1, "N1", "DSA-1", "critical", true), finding(2, "N2", "DSA-2", "high", false))
	store, worker, sink := vulnRules(t, highRule)
	cursor := &memCursor{}
	w := newVulnWatcherWithCursor(source, store, worker, cursor)

	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 {
		t.Fatalf("existing findings must not alert: %+v", sink.snapshot())
	}
	if !cursor.set || cursor.val != 2 {
		t.Fatalf("cursor = %d (set %v), want 2", cursor.val, cursor.set)
	}
}

func TestVulnWatcherAlertsANewFindingOnce(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	cursor := &memCursor{set: true}
	w := newVulnWatcherWithCursor(source, store, worker, cursor)

	source.add(finding(1, "N1", "DSA-1", "critical", false))
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %+v", hits)
	}
	h := hits[0]
	if h.NodeUUID != "N1" || h.Entity != "N1:DSA-1" || h.EnvironmentID != 1 || h.Environment != "prod" {
		t.Fatalf("unexpected attribution: %+v", h)
	}
	for _, want := range []string{"DSA-1", "critical", "openssl 3.0.11-1", "fixed in 3.0.13-1", "n1"} {
		if !strings.Contains(h.Detail, want) {
			t.Errorf("detail %q is missing %q", h.Detail, want)
		}
	}
	sink.reset()
	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 {
		t.Fatalf("a finding alerts once: %+v", sink.snapshot())
	}
}

func TestVulnWatcherRespectsThresholdScopeAndEnvironment(t *testing.T) {
	source := &fakeFindingSource{}
	nodeRule := AlertRule{Model: ruleWithID(2), Name: "n2-any", Source: SourceVulnFinding, VulnMinSeverity: VulnMinAny, NodeUUID: "N2", Enabled: true}
	envRule := AlertRule{Model: ruleWithID(3), Name: "env2-kev", Source: SourceVulnFinding, VulnMinSeverity: VulnMinKEV, EnvironmentID: 2, Enabled: true}
	store, worker, sink := vulnRules(t, highRule, nodeRule, envRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})

	source.add(
		finding(1, "N1", "DSA-1", "medium", false),  // below high; not N2; not env 2
		finding(2, "N2", "DSA-2", "unknown", false), // only the node-scoped "any" rule
		finding(3, "N3", "DSA-3", "low", true),      // KEV: high rule matches; env rule is env 2 only
	)
	w.Sweep(context.Background())
	got := map[string]bool{}
	for _, h := range sink.snapshot() {
		got[fmt.Sprintf("%s/%s", h.RuleName, h.NodeUUID)] = true
	}
	want := map[string]bool{"n2-any/N2": true, "high/N3": true}
	if len(got) != len(want) {
		t.Fatalf("hits = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("missing hit %s in %v", k, got)
		}
	}
}

// A new advisory that hits many nodes is one notification, not one each.
func TestVulnWatcherGroupsNodesPerAdvisory(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	for i := uint(1); i <= 12; i++ {
		source.add(finding(i, fmt.Sprintf("N%d", i), "DSA-9", "critical", false))
	}
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 {
		t.Fatalf("want one grouped hit, got %d", len(hits))
	}
	if hits[0].NodeUUID != "" || hits[0].Entity != "DSA-9" {
		t.Fatalf("a multi-node hit has no single node: %+v", hits[0])
	}
	if !strings.Contains(hits[0].Detail, "12 nodes") || !strings.Contains(hits[0].Detail, "and 2 more") {
		t.Fatalf("detail should count nodes and elide the rest: %q", hits[0].Detail)
	}
}

// An enrolment that brings many findings must not page once per advisory.
func TestVulnWatcherCapsHitsPerSweepWorstFirst(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	for i := uint(1); i <= 14; i++ {
		source.add(finding(i, "N1", fmt.Sprintf("DSA-%02d", i), "high", false))
	}
	source.add(finding(15, "N1", "DSA-KEV", "high", true)) // listed last, ranked first
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != maxVulnHitsPerRule+1 {
		t.Fatalf("want %d hits (cap + digest), got %d", maxVulnHitsPerRule+1, len(hits))
	}
	if !strings.Contains(hits[0].Detail, "DSA-KEV") {
		t.Fatalf("the KEV advisory must come first: %q", hits[0].Detail)
	}
	digest := hits[len(hits)-1]
	if !strings.Contains(digest.Detail, "5 more advisories") {
		t.Fatalf("digest should count the rest: %q", digest.Detail)
	}
}

// A cursor read failure must not replay history or lose the cursor.
func TestVulnWatcherSkipsWhenTheCursorIsUnavailable(t *testing.T) {
	source := &fakeFindingSource{}
	source.add(finding(1, "N1", "DSA-1", "critical", true))
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{fail: true})
	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 || source.calls != 0 {
		t.Fatalf("no cursor, no work: hits=%d calls=%d", len(sink.snapshot()), source.calls)
	}
}

// Without rules the cursor still advances, so a rule created later only
// alerts on findings that appear after it.
func TestVulnWatcherAdvancesWithoutRules(t *testing.T) {
	source := &fakeFindingSource{}
	source.add(finding(1, "N1", "DSA-1", "critical", true))
	store, worker, sink := vulnRules(t)
	cursor := &memCursor{set: true}
	w := newVulnWatcherWithCursor(source, store, worker, cursor)
	w.Sweep(context.Background())
	if cursor.val != 1 {
		t.Fatalf("cursor = %d, want 1", cursor.val)
	}
	if len(sink.snapshot()) != 0 {
		t.Fatal("no rules, no hits")
	}
}

// The node may be deleted before the sweep: name it by UUID.
func TestVulnWatcherFallsBackToTheNodeUUID(t *testing.T) {
	source := &fakeFindingSource{}
	f := finding(1, "GONE-NODE", "DSA-1", "critical", false)
	f.Hostname = ""
	source.add(f)
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || !strings.Contains(hits[0].Detail, "GONE-NODE") {
		t.Fatalf("detail must name the node by UUID: %+v", hits)
	}
}

// One advisory can cover several packages on one node (an Ubuntu USN for
// several source packages). That is one node, not "2 nodes: web-01, web-01".
func TestVulnWatcherCountsNodesNotFindings(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	second := finding(2, "N1", "USN-1", "high", false)
	second.Package = "openssl-libs"
	source.add(finding(1, "N1", "USN-1", "high", false), second, finding(3, "N2", "USN-2", "high", false), finding(4, "N3", "USN-2", "high", false), finding(5, "N3", "USN-2", "high", false))
	w.Sweep(context.Background())
	byEntity := map[string]Hit{}
	for _, h := range sink.snapshot() {
		byEntity[h.Entity] = h
	}
	single, ok := byEntity["N1:USN-1"]
	if !ok || single.NodeUUID != "N1" {
		t.Fatalf("one node with two packages is a single-node hit: %+v", sink.snapshot())
	}
	multi, ok := byEntity["USN-2"]
	if !ok || !strings.Contains(multi.Detail, "2 nodes") || strings.Count(multi.Detail, "n3") != 1 {
		t.Fatalf("nodes are counted once each: %+v", sink.snapshot())
	}
}

type budgetKey struct {
	kind          string
	ruleID, envID uint
}

type memVulnBudget struct {
	used     map[budgetKey]int
	digested map[budgetKey]bool
}

func newMemVulnBudget() *memVulnBudget {
	return &memVulnBudget{used: map[budgetKey]int{}, digested: map[budgetKey]bool{}}
}

func (b *memVulnBudget) take(_ context.Context, kind string, ruleID, envID uint, n int) (int, bool, error) {
	k := budgetKey{kind, ruleID, envID}
	granted := grantVuln(b.used[k], n)
	b.used[k] += n
	if granted == n || b.digested[k] {
		return granted, false, nil
	}
	b.digested[k] = true
	return granted, true, nil
}

// Hits are bounded per rule and environment per window, not per sweep: an
// inventory rollout or a re-match spread over many sweeps cannot page once a
// minute.
func TestVulnWatcherBudgetsHitsAcrossSweeps(t *testing.T) {
	ctx := context.Background()
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.budget = newMemVulnBudget()
	for i := uint(1); i <= 8; i++ {
		source.add(finding(i, "N1", fmt.Sprintf("DSA-%02d", i), "high", false))
	}
	w.Sweep(ctx)
	if got := len(sink.snapshot()); got != 8 {
		t.Fatalf("first sweep: want 8 hits, got %d", got)
	}
	sink.reset()
	for i := uint(9); i <= 13; i++ {
		source.add(finding(i, "N2", fmt.Sprintf("DSA-%02d", i), "high", false))
	}
	w.Sweep(ctx)
	hits := sink.snapshot()
	if len(hits) != 3 || !strings.Contains(hits[2].Detail, "3 more advisories") {
		t.Fatalf("second sweep: want the 2 left in the window plus a digest, got %+v", hits)
	}
	sink.reset()
	source.add(finding(14, "N3", "DSA-14", "critical", true))
	w.Sweep(ctx)
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("window spent and its digest sent: want no hits, got %+v", got)
	}
}

func TestGrantVuln(t *testing.T) {
	for _, tt := range []struct{ used, n, want int }{
		{0, 3, 3}, {0, 15, maxVulnHitsPerRule}, {8, 5, 2}, {maxVulnHitsPerRule, 1, 0}, {maxVulnHitsPerRule + 5, 4, 0},
	} {
		if got := grantVuln(tt.used, tt.n); got != tt.want {
			t.Errorf("grantVuln(%d, %d) = %d, want %d", tt.used, tt.n, got, tt.want)
		}
	}
}

func TestRedisVulnBudgetLive(t *testing.T) {
	client, ok := liveRedis(t)
	if !ok {
		t.Skip("REDIS_URL not set; live budget test skipped")
	}
	ctx := context.Background()
	now := time.Now()
	b := &redisVulnBudget{client: client, now: func() time.Time { return now }}
	ruleID := uint(now.UnixNano() % 1_000_000_000) // a fresh key per run
	if granted, digest, err := b.take(ctx, vulnKindNew, ruleID, 1, 7); err != nil || granted != 7 || digest {
		t.Fatalf("first take = %d, %v, %v", granted, digest, err)
	}
	if granted, digest, err := b.take(ctx, vulnKindNew, ruleID, 1, 7); err != nil || granted != maxVulnHitsPerRule-7 || !digest {
		t.Fatalf("second take = %d, %v, %v", granted, digest, err)
	}
	if granted, digest, err := b.take(ctx, vulnKindNew, ruleID, 1, 1); err != nil || granted != 0 || digest {
		t.Fatalf("third take = %d, %v, %v", granted, digest, err)
	}
	if granted, _, err := b.take(ctx, vulnKindNew, ruleID, 2, 1); err != nil || granted != 1 {
		t.Fatalf("another environment has its own budget: %d, %v", granted, err)
	}
	now = now.Add(vulnWindow)
	if granted, _, err := b.take(ctx, vulnKindNew, ruleID, 1, 1); err != nil || granted != 1 {
		t.Fatalf("the next window starts fresh: %d, %v", granted, err)
	}
}

// escalation is base after it became known-exploited or rose in severity;
// id is the escalation's own id.
func escalation(id uint, base FindingSnapshot, prevSeverity string, prevKEV bool) FindingSnapshot {
	base.ID, base.Escalated, base.PrevSeverity, base.PrevKEV = id, true, prevSeverity, prevKEV
	return base
}

var kevRule = AlertRule{Model: ruleWithID(4), Name: "kev", Source: SourceVulnFinding, VulnMinSeverity: VulnMinKEV, Enabled: true, ChannelIDs: "[1]"}

// CISA adding a CVE the fleet already has is the common KEV case: the
// finding alerts again, once, when it becomes known-exploited.
func TestVulnWatcherAlertsEscalationsOnce(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, kevRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.escalations = &memCursor{set: true}
	source.escalate(escalation(1, finding(40, "N1", "DSA-1", "high", true), "high", false))
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || hits[0].Entity != "N1:DSA-1:escalated" || !strings.Contains(hits[0].Detail, "now known exploited") {
		t.Fatalf("want one escalation hit, got %+v", hits)
	}
	sink.reset()
	w.Sweep(context.Background())
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("an escalation alerts once: %+v", got)
	}
}

// An escalation alerts only the rules it newly matches: a high rule already
// covered a high finding that turns critical.
func TestVulnWatcherEscalationNeedsANewMatch(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.escalations = &memCursor{set: true}
	source.escalate(
		escalation(1, finding(40, "N1", "DSA-1", "high", false), "medium", false),
		escalation(2, finding(41, "N2", "DSA-2", "critical", false), "high", false),
	)
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || !strings.Contains(hits[0].Detail, "DSA-1") || !strings.Contains(hits[0].Detail, "was medium") {
		t.Fatalf("want only the newly high finding, got %+v", hits)
	}
}

// Overlapping match transactions can commit a lower ID after a higher one.
// A sweep only takes IDs the previous sweep already listed, so one written
// by a slower transaction is never passed by the cursor. No clocks involved.
func TestVulnWatcherWaitsForFindingsToSettle(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	cursor := &memCursor{set: true}
	w := newVulnWatcherWithCursor(source, store, worker, cursor)
	w.settle = true
	source.add(finding(1, "N1", "DSA-1", "critical", false), finding(3, "N3", "DSA-3", "critical", false))
	w.Sweep(context.Background())
	if hits := sink.snapshot(); len(hits) != 0 || cursor.val != 0 {
		t.Fatalf("nothing is taken before it settles: hits %+v, cursor %d", hits, cursor.val)
	}
	source.add(finding(2, "N2", "DSA-2", "critical", false)) // a slower transaction commits
	w.Sweep(context.Background())
	if hits := sink.snapshot(); len(hits) != 3 || cursor.val != 3 {
		t.Fatalf("all three once settled: hits %+v, cursor %d", hits, cursor.val)
	}
}

// The cursor is saved every sweep, so its expiry only lapses when the
// watcher stops running, not during a quiet week.
func TestVulnWatcherKeepsTheCursorAliveWhenQuiet(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, _ := vulnRules(t, highRule)
	cursor := &memCursor{set: true, val: 7}
	w := newVulnWatcherWithCursor(source, store, worker, cursor)
	w.Sweep(context.Background())
	if cursor.saves != 1 || cursor.val != 7 {
		t.Fatalf("saves=%d val=%d, want 1 and 7", cursor.saves, cursor.val)
	}
}

type denyLock struct{}

func (denyLock) acquire(context.Context) bool { return false }

// Only one osctrl-tls replica sweeps at a time: concurrent sweeps would move
// the cursor backwards and send grouped hits twice.
func TestVulnWatcherSweepsOnlyWithTheLock(t *testing.T) {
	source := &fakeFindingSource{}
	source.add(finding(1, "N1", "DSA-1", "critical", true))
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.lock = denyLock{}
	w.Sweep(context.Background())
	if len(sink.snapshot()) != 0 || source.calls != 0 {
		t.Fatalf("another replica holds the sweep: hits=%d calls=%d", len(sink.snapshot()), source.calls)
	}
}

// A corrupt cursor value restarts from the newest finding instead of
// stopping vulnerability alerts until someone deletes the key.
func TestParseVulnCursor(t *testing.T) {
	if id, ok := parseVulnCursor("123"); !ok || id != 123 {
		t.Fatalf("parseVulnCursor(123) = %d, %v", id, ok)
	}
	for _, bad := range []string{"", "abc", "-1", "99999999999999999999999"} {
		if _, ok := parseVulnCursor(bad); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

// Turning NVD on can escalate thousands of findings at once. They have their
// own hourly budget: a new finding in the same hour still alerts.
func TestVulnWatcherEscalationsDoNotStarveNewFindings(t *testing.T) {
	source := &fakeFindingSource{}
	store, worker, sink := vulnRules(t, highRule)
	w := newVulnWatcherWithCursor(source, store, worker, &memCursor{set: true})
	w.escalations = &memCursor{set: true}
	w.budget = newMemVulnBudget()
	for i := uint(1); i <= 15; i++ {
		source.escalate(escalation(i, finding(100+i, "N1", fmt.Sprintf("DSA-%02d", i), "high", false), "unknown", false))
	}
	w.Sweep(context.Background())
	sink.reset()
	source.add(finding(1, "N2", "DSA-NEW", "critical", true))
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || !strings.Contains(hits[0].Detail, "DSA-NEW") {
		t.Fatalf("a new finding after an escalation flood must alert: %+v", hits)
	}
}
