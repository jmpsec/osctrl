package alerts

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// vuln_watcher.go — vulnerability-finding alerts.
//
// osctrl-api's vulnerability worker writes findings to the shared database.
// This watcher, in osctrl-tls next to the dispatch worker, polls for new
// confirmed findings and turns them into hits for SourceVulnFinding rules.
//
// A finding alerts once: the cursor is the last finding ID processed, and a
// finding that resolves and reopens keeps its ID. The cursor lives in Redis
// so a restart does not re-alert; when it is missing (first enable, Redis
// flushed) the watcher starts from the newest finding instead of replaying
// history.

const (
	// vulnBatch bounds one sweep; a bigger backlog drains over sweeps.
	vulnBatch = 2000
	// maxVulnHitsPerRule caps advisory hits per rule and environment per
	// vulnWindow, across sweeps and osctrl-tls replicas; the rest collapse
	// into one digest hit per window. A node's first inventory, a rollout or
	// a fleet re-match spread over many sweeps stays bounded.
	maxVulnHitsPerRule = 10
	// vulnWindow is the budget window.
	vulnWindow = time.Hour
	// maxVulnNodesInDetail bounds the node list in one hit's detail.
	maxVulnNodesInDetail = 10
)

// FindingSnapshot is one new confirmed finding as the watcher sees it.
type FindingSnapshot struct {
	ID               uint
	NodeUUID         string
	Hostname         string // empty when the node was deleted
	EnvironmentID    uint
	Environment      string
	AdvisoryID       string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	KEV              bool
}

// FindingSource lists findings for the watcher. Implemented in osctrl-tls
// over pkg/vulns; tests substitute their own.
type FindingSource interface {
	// FindingsAfter returns open confirmed findings with ID > afterID,
	// lowest ID first, at most limit.
	FindingsAfter(ctx context.Context, afterID uint, limit int) ([]FindingSnapshot, error)
	// LatestFindingID returns the highest finding ID, 0 when there is none.
	LatestFindingID(ctx context.Context) (uint, error)
}

// vulnCursor persists the last processed finding ID. ok is false when no
// cursor has been stored yet.
type vulnCursor interface {
	load(ctx context.Context) (id uint, ok bool, err error)
	save(ctx context.Context, id uint) error
}

type redisVulnCursor struct{ client *redis.Client }

func vulnCursorKey() string { return keyPrefix + "vuln:cursor" }

func (c *redisVulnCursor) load(ctx context.Context) (uint, bool, error) {
	raw, err := c.client.Get(ctx, vulnCursorKey()).Result()
	if errors.Is(err, redis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("corrupt vulnerability cursor %q: %w", raw, err)
	}
	if id > uint64(^uint(0)) {
		return 0, false, fmt.Errorf("corrupt vulnerability cursor %q: value out of range for uint", raw)
	}
	return uint(id), true, nil
}

func (c *redisVulnCursor) save(ctx context.Context, id uint) error {
	return c.client.Set(ctx, vulnCursorKey(), strconv.FormatUint(uint64(id), 10), 0).Err()
}

// vulnBudget meters advisory hits per rule and environment per window.
// take reserves n hits and returns how many fit, and whether this caller
// sends the window's one digest for the rest.
type vulnBudget interface {
	take(ctx context.Context, ruleID, envID uint, n int) (granted int, digest bool, err error)
}

// grantVuln is how many of n hits fit a window that already counted used.
func grantVuln(used, n int) int {
	return max(0, min(n, maxVulnHitsPerRule-used))
}

type redisVulnBudget struct {
	client *redis.Client
	now    func() time.Time
}

func (b *redisVulnBudget) take(ctx context.Context, ruleID, envID uint, n int) (int, bool, error) {
	key := fmt.Sprintf("%svuln:budget:%d:%d:%d", keyPrefix, ruleID, envID, b.now().Truncate(vulnWindow).Unix())
	pipe := b.client.TxPipeline()
	used := pipe.IncrBy(ctx, key, int64(n))
	pipe.Expire(ctx, key, 2*vulnWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, false, err
	}
	granted := grantVuln(int(used.Val())-n, n)
	if granted == n {
		return granted, false, nil
	}
	digest, err := b.client.SetNX(ctx, key+":digest", 1, 2*vulnWindow).Result()
	return granted, digest, err
}

// VulnWatcher polls new findings and emits hits to the dispatch worker.
type VulnWatcher struct {
	source FindingSource
	store  *Store
	worker *Worker
	cursor vulnCursor
	// budget is nil in tests that only need the per-sweep cap.
	budget vulnBudget
}

// NewVulnWatcher builds the watcher over the shared Redis client.
func NewVulnWatcher(source FindingSource, store *Store, worker *Worker, client *redis.Client) *VulnWatcher {
	w := &VulnWatcher{source: source, store: store, worker: worker}
	if client != nil {
		w.cursor = &redisVulnCursor{client: client}
		w.budget = &redisVulnBudget{client: client, now: time.Now}
	}
	return w
}

// newVulnWatcherWithCursor injects a cursor store (tests).
func newVulnWatcherWithCursor(source FindingSource, store *Store, worker *Worker, cursor vulnCursor) *VulnWatcher {
	return &VulnWatcher{source: source, store: store, worker: worker, cursor: cursor}
}

// Sweep processes findings recorded since the last sweep.
func (w *VulnWatcher) Sweep(ctx context.Context) {
	if w == nil || w.worker == nil || w.store == nil || w.cursor == nil || w.source == nil {
		return
	}
	after, ok, err := w.cursor.load(ctx)
	if err != nil {
		// Fail closed: replaying every finding on a Redis blip would page
		// the whole fleet; a delayed alert is the lesser harm.
		log.Warn().Err(err).Msg("alert vulnerability sweep: cursor unavailable, skipping")
		return
	}
	if !ok {
		latest, err := w.source.LatestFindingID(ctx)
		if err != nil {
			log.Err(err).Msg("alert vulnerability sweep: error reading the latest finding")
			return
		}
		if err := w.cursor.save(ctx, latest); err != nil {
			log.Err(err).Msg("alert vulnerability sweep: error initializing the cursor")
		}
		return
	}
	findings, err := w.source.FindingsAfter(ctx, after, vulnBatch)
	if err != nil {
		log.Err(err).Msg("alert vulnerability sweep: error listing findings")
		return
	}
	if len(findings) == 0 {
		return
	}
	if hits := vulnHits(w.store.Snapshot().vulnFinding, findings, w.grant(ctx)); len(hits) > 0 {
		w.worker.Enqueue(hits)
	}
	// Saved after enqueueing: a failed save replays this batch next sweep,
	// and the claim gate collapses the repeats inside the cooldown.
	if err := w.cursor.save(ctx, findings[len(findings)-1].ID); err != nil {
		log.Err(err).Msg("alert vulnerability sweep: error saving the cursor")
	}
}

// Run sweeps on the interval until stop closes.
func (w *VulnWatcher) Run(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			w.Sweep(context.Background())
		}
	}
}

// grant meters a rule's hits for one environment. Without a budget, or when
// Redis fails, it falls back to the per-sweep cap: alerting stays available
// and still bounded.
func (w *VulnWatcher) grant(ctx context.Context) func(r *compiledRule, env uint, n int) (int, bool) {
	return func(r *compiledRule, env uint, n int) (int, bool) {
		if w.budget != nil {
			granted, digest, err := w.budget.take(ctx, r.id, env, n)
			if err == nil {
				return granted, digest
			}
			log.Warn().Err(err).Msg("alert vulnerability sweep: budget unavailable, capping this sweep only")
		}
		granted := min(n, maxVulnHitsPerRule)
		return granted, granted < n
	}
}

// vulnHits turns findings into hits. Per rule and environment, findings are
// grouped by advisory, so an advisory affecting 2,000 nodes is one
// notification listing them. At most maxVulnHitsPerRule advisories are
// sent per rule and environment per sweep, worst first (KEV, then
// severity); the rest collapse into one digest hit.
func vulnHits(rules []compiledRule, findings []FindingSnapshot, grant func(r *compiledRule, env uint, n int) (int, bool)) []Hit {
	var hits []Hit
	for i := range rules {
		r := &rules[i]
		type nodeAdvisory struct {
			env            uint
			advisory, node string
		}
		groups := map[uint]map[string][]FindingSnapshot{} // env → advisory → one finding per node
		seen := map[nodeAdvisory]bool{}
		var envOrder []uint
		for _, f := range findings {
			if !r.ruleApplies(f.EnvironmentID) {
				continue
			}
			if r.nodeScope != "" && r.nodeScope != f.NodeUUID {
				continue
			}
			if !vulnMatches(r.vulnMin, f.Severity, f.KEV) {
				continue
			}
			// An advisory can cover several packages on one node; it is
			// still one affected node.
			key := nodeAdvisory{f.EnvironmentID, f.AdvisoryID, f.NodeUUID}
			if seen[key] {
				continue
			}
			seen[key] = true
			byAdvisory := groups[f.EnvironmentID]
			if byAdvisory == nil {
				byAdvisory = map[string][]FindingSnapshot{}
				groups[f.EnvironmentID] = byAdvisory
				envOrder = append(envOrder, f.EnvironmentID)
			}
			byAdvisory[f.AdvisoryID] = append(byAdvisory[f.AdvisoryID], f)
		}
		for _, env := range envOrder {
			byAdvisory := groups[env]
			advisories := make([]string, 0, len(byAdvisory))
			for id := range byAdvisory {
				advisories = append(advisories, id)
			}
			sort.Slice(advisories, func(a, b int) bool {
				fa, fb := byAdvisory[advisories[a]][0], byAdvisory[advisories[b]][0]
				if fa.KEV != fb.KEV {
					return fa.KEV
				}
				if ra, rb := vulnSeverityRank[fa.Severity], vulnSeverityRank[fb.Severity]; ra != rb {
					return ra > rb
				}
				return advisories[a] < advisories[b]
			})
			granted, digest := grant(r, env, len(advisories))
			for _, id := range advisories[:granted] {
				hits = append(hits, vulnAdvisoryHit(r, byAdvisory[id]))
			}
			if granted < len(advisories) && digest {
				hits = append(hits, vulnDigestHit(r, advisories[granted:], byAdvisory))
			}
		}
	}
	return hits
}

func nodeLabel(f FindingSnapshot) string {
	if f.Hostname != "" {
		return f.Hostname
	}
	return f.NodeUUID
}

func vulnAdvisoryHit(r *compiledRule, group []FindingSnapshot) Hit {
	f := group[0]
	label := f.Severity
	if f.KEV {
		label += ", known exploited"
	}
	fix := "no fix yet"
	if f.FixedVersion != "" {
		fix = "fixed in " + f.FixedVersion
	}
	h := Hit{
		RuleID: r.id, RuleName: r.name,
		EnvironmentID: f.EnvironmentID, Environment: f.Environment,
		CooldownMinutes: r.cooldownMinutes, Channels: r.channels,
	}
	if len(group) == 1 {
		h.NodeUUID = f.NodeUUID
		h.Entity = f.NodeUUID + ":" + f.AdvisoryID
		h.Detail = truncateDetail(fmt.Sprintf("%s (%s) affects %s %s on %s (%s)",
			f.AdvisoryID, label, f.Package, f.InstalledVersion, nodeLabel(f), fix))
		return h
	}
	names := make([]string, 0, maxVulnNodesInDetail)
	for _, g := range group[:min(len(group), maxVulnNodesInDetail)] {
		names = append(names, nodeLabel(g))
	}
	detail := fmt.Sprintf("%s (%s) affects %s on %d nodes (%s): %s",
		f.AdvisoryID, label, f.Package, len(group), fix, strings.Join(names, ", "))
	if len(group) > maxVulnNodesInDetail {
		detail += fmt.Sprintf(" and %d more", len(group)-maxVulnNodesInDetail)
	}
	h.Entity = f.AdvisoryID
	h.Detail = truncateDetail(detail)
	return h
}

func vulnDigestHit(r *compiledRule, rest []string, byAdvisory map[string][]FindingSnapshot) Hit {
	nodes := map[string]bool{}
	for _, id := range rest {
		for _, f := range byAdvisory[id] {
			nodes[f.NodeUUID] = true
		}
	}
	first := byAdvisory[rest[0]][0]
	return Hit{
		RuleID: r.id, RuleName: r.name,
		EnvironmentID: first.EnvironmentID, Environment: first.Environment,
		Entity: "vuln-digest",
		Detail: truncateDetail(fmt.Sprintf("%d more advisories newly affect %d node(s) in %s; this rule notifies at most %d advisories per hour, so see the Vulnerabilities page for the rest",
			len(rest), len(nodes), first.Environment, maxVulnHitsPerRule)),
		CooldownMinutes: r.cooldownMinutes, Channels: r.channels,
	}
}
