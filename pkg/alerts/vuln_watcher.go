package alerts

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
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
// flushed, corrupt, or expired after a week without sweeps) the watcher
// starts from the newest finding instead of replaying history.
//
// A finding that later becomes known-exploited, or rises in severity, is
// recorded by osctrl-api as an escalation. A second cursor reads those the
// same way, and an escalation alerts the rules it newly matches.

const (
	// vulnBatch bounds one sweep; a bigger backlog drains over sweeps.
	// ponytail: ID order, not KEV first; a 150k-finding backlog drains in
	// under ten minutes at this size.
	vulnBatch = 20000
	// vulnCursorTTL expires a cursor no sweep has refreshed for a week, so
	// re-enabling alerts after a long pause starts from now.
	vulnCursorTTL = 7 * 24 * time.Hour
	// vulnLockTTL bounds how long a crashed sweeper blocks the others; a
	// live one releases the lock when its sweep ends.
	vulnLockTTL = 5 * time.Minute
	// vulnSweepTimeout ends a stuck sweep before its lock expires, so two
	// replicas never sweep at once.
	vulnSweepTimeout = vulnLockTTL - 30*time.Second
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

// FindingSnapshot is one new confirmed finding, or one escalation of an
// open finding, as the watcher sees it.
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
	// Escalated marks an escalation: the finding became known-exploited or
	// rose in severity. PrevSeverity and PrevKEV are what it was.
	Escalated    bool
	PrevSeverity string
	PrevKEV      bool
	// FindingID is the escalated finding (ID is the escalation's own).
	FindingID uint
}

// FindingSource lists findings for the watcher. Implemented in osctrl-tls
// over pkg/vulns; tests substitute their own.
type FindingSource interface {
	// FindingsAfter returns open confirmed findings with ID > afterID,
	// lowest ID first, at most limit.
	FindingsAfter(ctx context.Context, afterID uint, limit int) ([]FindingSnapshot, error)
	// LatestFindingID returns the highest finding ID, 0 when there is none.
	LatestFindingID(ctx context.Context) (uint, error)
	// EscalationsAfter returns escalations of open confirmed findings with
	// escalation ID > afterID, lowest first, at most limit. ID is the
	// escalation's.
	EscalationsAfter(ctx context.Context, afterID uint, limit int) ([]FindingSnapshot, error)
	// LatestEscalationID returns the highest escalation ID, 0 when none.
	LatestEscalationID(ctx context.Context) (uint, error)
}

// vulnCursor persists the last processed finding ID. ok is false when no
// cursor has been stored yet.
type vulnCursor interface {
	load(ctx context.Context) (id uint, ok bool, err error)
	save(ctx context.Context, id uint) error
}

type redisVulnCursor struct {
	client *redis.Client
	key    string
}

func vulnCursorKey() string { return keyPrefix + "vuln:cursor" }

func vulnEscalationCursorKey() string { return keyPrefix + "vuln:escalation-cursor" }

func (c *redisVulnCursor) load(ctx context.Context) (uint, bool, error) {
	raw, err := c.client.Get(ctx, c.key).Result()
	if errors.Is(err, redis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, ok := parseVulnCursor(raw)
	if !ok {
		// Restart from the newest instead of stopping alerts for good.
		log.Warn().Str("key", c.key).Msg("alert vulnerability sweep: corrupt cursor, restarting from the newest")
		return 0, false, nil
	}
	return id, true, nil
}

// parseVulnCursor reads a stored cursor; ok is false for anything that is
// not a finding ID.
func parseVulnCursor(raw string) (uint, bool) {
	id, err := strconv.ParseUint(raw, 10, strconv.IntSize)
	if err != nil {
		return 0, false
	}
	return uint(id), true
}

func (c *redisVulnCursor) save(ctx context.Context, id uint) error {
	return c.client.Set(ctx, c.key, strconv.FormatUint(uint64(id), 10), vulnCursorTTL).Err()
}

// vulnLock lets one osctrl-tls replica sweep per interval: concurrent
// sweeps would move the cursor backwards and send grouped hits twice.
type vulnLock interface {
	acquire(ctx context.Context) bool
	release(ctx context.Context)
}

type redisVulnLock struct {
	client *redis.Client
	token  string // this holder's value, so release never frees another's lock
}

func vulnLockKey() string { return keyPrefix + "vuln:sweep" }

func (l *redisVulnLock) acquire(ctx context.Context) bool {
	token := strconv.FormatUint(rand.Uint64(), 36)
	ok, err := l.client.SetNX(ctx, vulnLockKey(), token, vulnLockTTL).Result()
	if err != nil {
		// The cursor needs Redis too; this sweep could not run anyway.
		log.Warn().Err(err).Msg("alert vulnerability sweep: lock unavailable, skipping")
		return false
	}
	if ok {
		l.token = token
	}
	return ok
}

// releaseScript deletes the lock only while it still holds this token.
var releaseScript = redis.NewScript(`if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) end return 0`)

func (l *redisVulnLock) release(ctx context.Context) {
	if err := releaseScript.Run(ctx, l.client, []string{vulnLockKey()}, l.token).Err(); err != nil && !errors.Is(err, redis.Nil) {
		log.Warn().Err(err).Msg("alert vulnerability sweep: releasing the lock failed; it expires on its own")
	}
}

// vulnBudget meters advisory hits per kind (new findings or escalations),
// rule and environment per window. take reserves n hits and returns how many
// fit, and whether this caller sends the window's one digest for the rest.
// The kinds are metered apart, so an escalation flood (turning NVD on) never
// starves a new finding.
type vulnBudget interface {
	take(ctx context.Context, kind string, ruleID, envID uint, n int) (granted int, digest bool, err error)
}

// Budget kinds.
const (
	vulnKindNew       = "new"
	vulnKindEscalated = "esc"
)

// grantVuln is how many of n hits fit a window that already counted used.
func grantVuln(used, n int) int {
	return max(0, min(n, maxVulnHitsPerRule-used))
}

type redisVulnBudget struct {
	client *redis.Client
	now    func() time.Time
}

func (b *redisVulnBudget) take(ctx context.Context, kind string, ruleID, envID uint, n int) (int, bool, error) {
	key := fmt.Sprintf("%svuln:budget:%s:%d:%d:%d", keyPrefix, kind, ruleID, envID, b.now().Truncate(vulnWindow).Unix())
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
	// escalations is the escalation cursor; nil skips that pass (tests).
	escalations vulnCursor
	// budget and lock are nil in tests that do not exercise them.
	budget vulnBudget
	lock   vulnLock
	// settle makes a sweep take only IDs the previous sweep listed:
	// overlapping match transactions can commit a lower ID after a higher
	// one, and waiting a sweep keeps the cursor from passing one still
	// being written. seen is that previous listing's highest ID per pass
	// (process-local: a replica taking over the lock waits one sweep).
	settle bool
	seen   map[string]uint
	// alerted is the findings cursor before the previous sweep's pass:
	// findings at or below it alerted before any escalation now being
	// taken was listed (settling takes an escalation a sweep later).
	alerted    uint
	hasAlerted bool
}

// NewVulnWatcher builds the watcher over the shared Redis client.
func NewVulnWatcher(source FindingSource, store *Store, worker *Worker, client *redis.Client) *VulnWatcher {
	w := &VulnWatcher{source: source, store: store, worker: worker, settle: true, seen: map[string]uint{}}
	if client != nil {
		w.cursor = &redisVulnCursor{client: client, key: vulnCursorKey()}
		w.escalations = &redisVulnCursor{client: client, key: vulnEscalationCursorKey()}
		w.budget = &redisVulnBudget{client: client, now: time.Now}
		w.lock = &redisVulnLock{client: client}
	}
	return w
}

// newVulnWatcherWithCursor injects a cursor store (tests).
func newVulnWatcherWithCursor(source FindingSource, store *Store, worker *Worker, cursor vulnCursor) *VulnWatcher {
	return &VulnWatcher{source: source, store: store, worker: worker, cursor: cursor, seen: map[string]uint{}}
}

// Sweep processes findings and escalations recorded since the last sweep.
func (w *VulnWatcher) Sweep(ctx context.Context) {
	if w == nil || w.worker == nil || w.store == nil || w.cursor == nil || w.source == nil {
		return
	}
	if w.lock != nil {
		if !w.lock.acquire(ctx) {
			return
		}
		defer w.lock.release(ctx)
	}
	before, ok := w.pass(ctx, vulnKindNew, w.cursor, w.source.LatestFindingID, w.source.FindingsAfter, nil)
	seenUpTo := before
	if w.settle && w.hasAlerted {
		seenUpTo = min(before, w.alerted)
	}
	if ok {
		w.alerted, w.hasAlerted = before, true
	}
	if w.escalations != nil && ok {
		// A finding earlier sweeps have not alerted yet alerts (or just
		// alerted) with its current state; its escalation is not news.
		seen := func(f FindingSnapshot) bool { return f.FindingID <= seenUpTo }
		w.pass(ctx, vulnKindEscalated, w.escalations, w.source.LatestEscalationID, w.source.EscalationsAfter, seen)
	}
}

// pass reads one feed (findings or escalations) from its cursor.
// It returns the cursor as it was before the pass (what earlier sweeps
// covered), and false when the cursor could not be read or listing failed. keep, when set, drops items before alerting
// (the cursor still moves past them).
func (w *VulnWatcher) pass(ctx context.Context, kind string, cursor vulnCursor, latest func(context.Context) (uint, error),
	list func(context.Context, uint, int) ([]FindingSnapshot, error), keep func(FindingSnapshot) bool) (uint, bool) {
	after, ok, err := cursor.load(ctx)
	if err != nil {
		// Fail closed: replaying every finding on a Redis blip would page
		// the whole fleet; a delayed alert is the lesser harm.
		log.Warn().Err(err).Msg("alert vulnerability sweep: cursor unavailable, skipping")
		return 0, false
	}
	if !ok {
		newest, err := latest(ctx)
		if err != nil {
			log.Err(err).Msg("alert vulnerability sweep: error reading the latest finding")
			return 0, false
		}
		if err := cursor.save(ctx, newest); err != nil {
			log.Err(err).Msg("alert vulnerability sweep: error initializing the cursor")
		}
		return newest, true
	}
	before := after
	items, err := list(ctx, after, vulnBatch)
	if err != nil {
		log.Err(err).Msg("alert vulnerability sweep: error listing findings")
		return 0, false
	}
	if w.settle {
		// Only IDs the previous sweep listed; the rest waits a sweep.
		limit := w.seen[kind]
		if len(items) > 0 {
			w.seen[kind] = items[len(items)-1].ID
		}
		settled := 0
		for settled < len(items) && items[settled].ID <= limit {
			settled++
		}
		items = items[:settled]
	}
	if len(items) > 0 {
		next := items[len(items)-1].ID
		if keep != nil {
			items = slices.DeleteFunc(items, func(f FindingSnapshot) bool { return !keep(f) })
		}
		if hits := vulnHits(w.store.Snapshot().vulnFinding, items, w.grant(ctx, kind)); len(hits) > 0 {
			w.worker.Enqueue(hits)
		}
		after = next
	}
	// Saved every sweep, after enqueueing: a failed save replays this batch
	// (the claim gate collapses repeats), and a quiet week does not expire
	// the cursor while the watcher runs.
	if err := cursor.save(ctx, after); err != nil {
		log.Err(err).Msg("alert vulnerability sweep: error saving the cursor")
	}
	return before, true
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
			ctx, cancel := context.WithTimeout(context.Background(), vulnSweepTimeout)
			w.Sweep(ctx)
			cancel()
		}
	}
}

// grant meters a rule's hits for one environment. Without a budget, or when
// Redis fails, it falls back to the per-sweep cap: alerting stays available
// and still bounded.
func (w *VulnWatcher) grant(ctx context.Context, kind string) func(r *compiledRule, env uint, n int) (int, bool) {
	return func(r *compiledRule, env uint, n int) (int, bool) {
		if w.budget != nil {
			granted, digest, err := w.budget.take(ctx, kind, r.id, env, n)
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
			// An escalation is news only to rules it newly matches.
			if f.Escalated && vulnMatches(r.vulnMin, f.PrevSeverity, f.PrevKEV) {
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
	switch {
	case f.Escalated && f.KEV && !f.PrevKEV:
		label += ", now known exploited"
	case f.Escalated:
		label += ", was " + f.PrevSeverity
		if f.KEV {
			label += ", known exploited"
		}
	case f.KEV:
		label += ", known exploited"
	}
	suffix := ""
	if f.Escalated {
		suffix = ":escalated" // apart from the finding's original hit
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
		h.Entity = f.NodeUUID + ":" + f.AdvisoryID + suffix
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
	h.Entity = f.AdvisoryID + suffix
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
	verb, entity := "newly affect", "vuln-digest"
	if first.Escalated {
		verb, entity = "became known exploited or more severe on", "vuln-digest:escalated"
	}
	return Hit{
		RuleID: r.id, RuleName: r.name,
		EnvironmentID: first.EnvironmentID, Environment: first.Environment,
		Entity: entity,
		Detail: truncateDetail(fmt.Sprintf("%d more advisories %s %d node(s) in %s; this rule notifies at most %d advisories per hour, so see the Vulnerabilities page for the rest",
			len(rest), verb, len(nodes), first.Environment, maxVulnHitsPerRule)),
		CooldownMinutes: r.cooldownMinutes, Channels: r.channels,
	}
}
