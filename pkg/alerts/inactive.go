package alerts

import (
	"context"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// inactive.go — node-inactive / node-recovered watcher (Stage 5).
//
// A periodic sweep compares every node's last_seen against the
// environment's inactive threshold and fires on *state transitions*:
//   - active → inactive: one node_inactive hit per node (deduped by
//     Redis state, not the per-hit cooldown key — the state IS the
//     cooldown)
//   - inactive → active: one node_recovered hit per node, but only when
//     at least one node_recovered rule exists (recovery alerts are
//     opt-in)
//
// Why sweep-based rather than log-arrival-based: inactivity is the
// *absence* of traffic, so it can only be observed by a clock, never by
// an event. The sweep runs on a ticker in osctrl-tls, batched per
// environment, never on the ingest path.
//
// State lives in a Redis set per environment (UUID membership), so a
// restart does not re-alert the whole fleet. On Redis errors the sweep
// fails open like the cooldown gate: availability of alerting beats
// perfect dedupe.

// NodeSnapshot is one node's liveness state as seen by the sweep.
type NodeSnapshot struct {
	UUID string
	// EnvironmentID / Environment identify the node's environment for
	// rule scoping (ruleApplies) and hit attribution respectively.
	EnvironmentID uint
	Environment   string
	Hostname      string
	Active        bool
	LastSeen      time.Time
}

// NodeSource produces node snapshots for the sweep. Implemented over
// the nodes manager in osctrl-tls; tests substitute their own.
type NodeSource interface {
	// InactiveNodes returns every node whose last_seen is older than
	// the given threshold, and the threshold itself is resolved per
	// environment by the implementation.
	InactiveNodes(ctx context.Context) ([]NodeSnapshot, error)
	// ActiveNodes returns every currently-active node (used to detect
	// recoveries of nodes previously marked inactive).
	ActiveNodes(ctx context.Context) ([]NodeSnapshot, error)
}

// inactiveState is the persistence surface the watcher needs (Redis
// set membership). *redis.Client satisfies it via the redisState
// adapter; tests substitute an in-memory map.
type inactiveState interface {
	load(ctx context.Context) (map[string]bool, error)
	save(ctx context.Context, inactive map[string]bool) error
}

// redisInactiveState adapts a Redis client to the inactiveState
// interface using a single set key.
type redisInactiveState struct {
	client *redis.Client
}

func (s *redisInactiveState) load(ctx context.Context) (map[string]bool, error) {
	members, err := s.client.SMembers(ctx, inactiveStateKey()).Result()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(members))
	for _, m := range members {
		out[m] = true
	}
	return out, nil
}

func (s *redisInactiveState) save(ctx context.Context, inactive map[string]bool) error {
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, inactiveStateKey())
	if len(inactive) > 0 {
		members := make([]interface{}, 0, len(inactive))
		for uuid := range inactive {
			members = append(members, uuid)
		}
		pipe.SAdd(ctx, inactiveStateKey(), members...)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// InactiveWatcher runs the sweep and emits hits to the dispatch worker.
type InactiveWatcher struct {
	source NodeSource
	store  *Store
	worker *Worker
	state  inactiveState
	// now is overridable for tests.
	now func() time.Time
}

// NewInactiveWatcher builds the watcher. worker may be nil (feature
// off mid-restart) — sweeps then no-op. A nil client builds a watcher
// with no persistence: every sweep re-evaluates transitions from
// scratch, so inactive nodes re-alert each pass (acceptable only for
// tests; production always passes the Redis client).
func NewInactiveWatcher(source NodeSource, store *Store, worker *Worker, client *redis.Client) *InactiveWatcher {
	w := &InactiveWatcher{source: source, store: store, worker: worker, now: time.Now}
	if client != nil {
		w.state = &redisInactiveState{client: client}
	}
	return w
}

// newInactiveWatcherWithState injects a custom state store (tests).
func newInactiveWatcherWithState(source NodeSource, store *Store, worker *Worker, state inactiveState) *InactiveWatcher {
	return &InactiveWatcher{source: source, store: store, worker: worker, state: state, now: time.Now}
}

// stateKey is the Redis set of UUIDs currently flagged inactive.
func inactiveStateKey() string {
	return keyPrefix + "inactive"
}

// Sweep runs one detection pass: mark newly-inactive nodes, unmark
// recovered ones, and enqueue hits for the transitions.
func (w *InactiveWatcher) Sweep(ctx context.Context) {
	if w == nil || w.worker == nil || w.store == nil {
		return
	}
	rs := w.store.Snapshot()
	if len(rs.nodeInactive) == 0 && len(rs.nodeRecovered) == 0 {
		return // no node-state rules: nothing to do, skip the queries entirely
	}

	inactive, err := w.source.InactiveNodes(ctx)
	if err != nil {
		log.Err(err).Msg("alert inactive sweep: error listing inactive nodes")
		return
	}
	// Only query actives when recovery rules exist.
	var active []NodeSnapshot
	if len(rs.nodeRecovered) > 0 {
		active, err = w.source.ActiveNodes(ctx)
		if err != nil {
			log.Err(err).Msg("alert inactive sweep: error listing active nodes")
			return
		}
	}

	previouslyInactive, stateErr := w.loadState(ctx)
	if stateErr != nil {
		// Fail open: proceed with an empty prior-state view. Worst case
		// on a Redis blip we re-alert nodes already flagged — the same
		// posture as the cooldown gate.
		log.Warn().Err(stateErr).Msg("alert inactive sweep: state unavailable, failing open")
		previouslyInactive = map[string]bool{}
	}

	now := w.now()
	var hits []Hit
	newlyInactive := map[string]bool{}

	// active → inactive transitions
	for _, node := range inactive {
		newlyInactive[node.UUID] = true
		if previouslyInactive[node.UUID] {
			continue
		}
		for i := range rs.nodeInactive {
			r := &rs.nodeInactive[i]
			if !r.ruleApplies(node.EnvironmentID) {
				continue
			}
			// Node-scoped rules only fire for their node.
			if r.nodeScope != "" && r.nodeScope != node.UUID {
				continue
			}
			hits = append(hits, Hit{
				RuleID:          r.id,
				RuleName:        r.name,
				EnvironmentID:   node.EnvironmentID,
				Environment:     node.Environment,
				NodeUUID:        node.UUID,
				Entity:          node.UUID,
				Detail:          fmt.Sprintf("%s last seen %s", node.Hostname, humanSince(now, node.LastSeen)),
				CooldownMinutes: r.cooldownMinutes,
				Channels:        r.channels,
			})
		}
	}

	// inactive → active transitions (only when recovery rules exist)
	if len(rs.nodeRecovered) > 0 {
		for _, node := range active {
			if !previouslyInactive[node.UUID] {
				continue
			}
			for i := range rs.nodeRecovered {
				r := &rs.nodeRecovered[i]
				if !r.ruleApplies(node.EnvironmentID) {
					continue
				}
				// Node-scoped rules only fire for their node.
				if r.nodeScope != "" && r.nodeScope != node.UUID {
					continue
				}
				hits = append(hits, Hit{
					RuleID:          r.id,
					RuleName:        r.name,
					EnvironmentID:   node.EnvironmentID,
					Environment:     node.Environment,
					NodeUUID:        node.UUID,
					Entity:          node.UUID,
					Detail:          fmt.Sprintf("%s seen again at %s", node.Hostname, node.LastSeen.Format(time.RFC3339)),
					CooldownMinutes: r.cooldownMinutes,
					Channels:        r.channels,
				})
			}
		}
	}

	// Persist the new state (replace the set wholesale — nodes that
	// recovered leave it).
	if err := w.saveState(ctx, newlyInactive); err != nil {
		log.Err(err).Msg("alert inactive sweep: error persisting state")
	}

	if len(hits) > 0 {
		w.worker.Enqueue(hits)
	}
}

// loadState reads the flagged-inactive UUID set.
func (w *InactiveWatcher) loadState(ctx context.Context) (map[string]bool, error) {
	if w.state == nil {
		return map[string]bool{}, nil
	}
	return w.state.load(ctx)
}

// saveState replaces the flagged set with the current pass's inactive
// UUIDs.
func (w *InactiveWatcher) saveState(ctx context.Context, inactive map[string]bool) error {
	if w.state == nil {
		return nil
	}
	return w.state.save(ctx, inactive)
}

// Run blocks running the sweep on the interval until stop closes.
func (w *InactiveWatcher) Run(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
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

// humanSince renders a coarse "x days / x hours ago" for hit details.
func humanSince(now, lastSeen time.Time) string {
	if lastSeen.IsZero() {
		return "never"
	}
	d := now.Sub(lastSeen)
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
}
