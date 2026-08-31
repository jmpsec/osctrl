package alerts

import (
	"regexp"
	"sync/atomic"
)

// rules.go — immutable rule snapshots with lock-free reads.
//
// The ingest goroutine calls Match* on every decoded batch. To keep that
// path allocation- and lock-free, rules live in an immutable *RuleSet
// published through an atomic.Pointer. Refresh builds a complete new
// snapshot off-path and swaps it in; readers either see the old or the
// new set, never a half-built one.

// MaxPatternLen caps an operator-supplied regex/substring length. Long
// patterns are a trivial DoS lever on a hot path.
const MaxPatternLen = 512

// MaxRulesPerEnv caps rule count per environment so a fleet of very
// matchy rules cannot make ingest O(huge). Enforced at create/update in
// the manager.
const MaxRulesPerEnv = 50

// compiledRule is a ready-to-evaluate rule: pattern precompiled (regex)
// or pre-lowercased (case-insensitive substring), fields precomputed.
type compiledRule struct {
	// identity for dedupe keys and history rows
	id   uint
	name string
	env  uint

	matchSubstring string // lowercased when matchField is set
	matchRegex     *regexp.Regexp

	// matchAny means MatchField was empty: evaluate against all fields.
	matchAny        bool
	matchFieldLower string

	// status-log filter: minimum severity that must match.
	// 0 = any, 1 = warning+, 2 = error only.
	minSeverity int

	cooldownMinutes int
	channels        []uint
}

// RuleSet is an immutable snapshot of all enabled rules, grouped by
// source so each ingest path only walks its own rules. The zero value
// (no rules) is valid and match-free.
type RuleSet struct {
	result []compiledRule
	status []compiledRule
	query  []compiledRule
	// nodeInactive / nodeRecovered are evaluated by the inactive-node
	// sweep (Stage 5), not the log matcher. They carry only identity +
	// cooldown + channels — no pattern.
	nodeInactive  []compiledRule
	nodeRecovered []compiledRule
}

// counts returns the number of compiled rules per bucket (test helper).
func (rs *RuleSet) counts() (result, status, query int) {
	return len(rs.result), len(rs.status), len(rs.query)
}

// empty reports whether the snapshot has no rules at all.
func (rs *RuleSet) empty() bool {
	return len(rs.result) == 0 && len(rs.status) == 0 && len(rs.query) == 0 &&
		len(rs.nodeInactive) == 0 && len(rs.nodeRecovered) == 0
}

// Store publishes rule snapshots. Safe for concurrent use; readers pull
// via Snapshot() which returns the current immutable set.
type Store struct {
	current atomic.Pointer[RuleSet]
}

// NewStore creates an empty rule store.
func NewStore() *Store {
	s := &Store{}
	s.current.Store(&RuleSet{})
	return s
}

// Snapshot returns the current immutable rule set. The returned pointer
// must be treated as read-only.
func (s *Store) Snapshot() *RuleSet {
	return s.current.Load()
}

// Publish atomically replaces the snapshot. Building the new RuleSet
// happens before this call, so the swap itself is a single word store.
func (s *Store) Publish(rs *RuleSet) {
	if rs == nil {
		rs = &RuleSet{}
	}
	s.current.Store(rs)
}
