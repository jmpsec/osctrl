// Package alerts evaluates operator-defined rules against osquery log
// traffic and node state, and dispatches notifications through configured
// channels (email, webhooks, …).
//
// Design constraints (hot-path first):
//
//   - The ingest path never reads the database or Redis to decide whether
//     a log line matches. Rules are served from an immutable RuleSet
//     snapshot loaded at boot / refresh; a config change swaps the
//     snapshot atomically (copy-on-write), so matching is lock-free.
//   - Regexes are compiled once per snapshot. Matching over a decoded
//     batch is O(rules) with no allocations beyond the hit slice.
//   - Cooldown/dedupe state lives in Redis with a TTL equal to the rule's
//     cooldown window, and is consulted by the dispatch worker — never
//     by the ingest goroutine.
//
// Row conventions follow pkg/logsinks: EnvironmentID=0 means the rule
// applies globally to every environment; per-env rows override. Rules are
// stored per source type so the ingest hook only walks rules registered
// for the log type it just decoded.
package alerts

import (
	"time"

	"gorm.io/gorm"
)

// NoEnvironmentID is the sentinel for global (non-env-scoped) rows.
// Mirrors settings.NoEnvironmentID / logsinks.NoEnvironmentID.
const NoEnvironmentID uint = 0

// Sources a rule can watch. The ingest hook only evaluates rules whose
// Source matches the data it just decoded, so unrelated rules cost
// nothing on any given path.
const (
	// SourceResultLog watches osquery scheduled-query result logs.
	SourceResultLog = "result_log"
	// SourceStatusLog watches osquery daemon status logs.
	SourceStatusLog = "status_log"
	// SourceQueryLog watches on-demand distributed query results.
	SourceQueryLog = "query_log"
	// SourceNodeInactive fires when a node crosses the inactive
	// threshold. Evaluated by a periodic sweep, not the ingest path.
	SourceNodeInactive = "node_inactive"
	// SourceNodeRecovered fires when a previously inactive node is
	// seen again. Evaluated by the same sweep.
	SourceNodeRecovered = "node_recovered"
)

// Match types. Substring is the operator default — regex is opt-in
// because an author-supplied pattern is a DoS vector otherwise.
const (
	MatchTypeSubstring = "substring"
	MatchTypeRegex     = "regex"
)

// AlertRule is one operator-defined alert. Name + EnvironmentID are
// unique together (gorm composite index below), mirroring saved
// queries and log sinks.
type AlertRule struct {
	gorm.Model
	Name          string `gorm:"uniqueIndex:idx_alert_rules_unique"`
	EnvironmentID uint   `gorm:"uniqueIndex:idx_alert_rules_unique"`
	// Source is one of the Source* constants.
	Source string `gorm:"index;size:32"`
	// MatchType is MatchTypeSubstring or MatchTypeRegex.
	MatchType string `gorm:"size:16"`
	// MatchField scopes the match to one column ("message" for status
	// logs, a column name for result/query logs). Empty = any field.
	MatchField string `gorm:"size:128"`
	// MatchValue is the substring or regex pattern.
	MatchValue string `gorm:"type:text"`
	// StatusSeverity filters status-log rules: "error", "warning" or
	// "any". Only consulted when Source == SourceStatusLog.
	StatusSeverity string `gorm:"size:16;default:any"`
	// CooldownMinutes suppresses repeat notifications for the same
	// rule+entity within this window. 0 = alert on every match (subject
	// to the global default cooldown).
	CooldownMinutes int `gorm:"default:0"`
	// ChannelIDs is a JSON-encoded array of alert_channel IDs. Empty
	// array = no channels yet; the rule matches but nothing is sent.
	ChannelIDs string `gorm:"type:text"`
	Enabled    bool
	Info       string
}

// TableName overrides the default table name.
func (AlertRule) TableName() string { return "alert_rules" }

// AlertChannel is one notification destination. Type + Config follow
// the logsinks pattern: Config is a JSON blob validated against the
// channel Registry (Stage 3); the typed form schema ships with the
// Registry so the SPA renders it generically.
type AlertChannel struct {
	gorm.Model
	Name          string `gorm:"uniqueIndex:idx_alert_channels_unique"`
	EnvironmentID uint   `gorm:"uniqueIndex:idx_alert_channels_unique"`
	// Type is the Registry key: "email", "webhook", …
	Type string `gorm:"index;size:32"`
	// Config is a JSON blob whose shape depends on Type.
	Config  string `gorm:"type:text"`
	Enabled bool
	Info    string
}

// TableName overrides the default table name.
func (AlertChannel) TableName() string { return "alert_channels" }

// AlertHistory records every notification the system sent, for the
// "recent alerts" view and for auditing. Written only by the dispatch
// worker (off the hot path); reads happen through the management API.
type AlertHistory struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// RuleID / ChannelID are denormalized as uint rather than FKs so
	// deleting a rule or channel does not cascade-delete history.
	RuleID      uint   `gorm:"index" json:"rule_id"`
	RuleName    string `gorm:"size:128" json:"rule_name"`
	ChannelID   uint   `gorm:"index" json:"channel_id"`
	ChannelName string `gorm:"size:128" json:"channel_name"`
	Environment string `gorm:"size:64;index" json:"environment"`
	NodeUUID    string `gorm:"size:64;index" json:"node_uuid"`
	// Entity is what matched: a hostname, a query name, or "node" for
	// inactive/recovered rules. Part of the Redis dedupe key.
	Entity string `gorm:"size:256" json:"entity"`
	// Detail is the rendered match context (bounded at match time).
	Detail string `gorm:"type:text" json:"detail"`
}

// TableName overrides the default table name.
func (AlertHistory) TableName() string { return "alert_history" }

// osquery status-log severities (matching osquery's internal levels):
// 0=INFO, 1=WARNING, 2=ERROR. Used by the status-log matcher filter.
const (
	osquerySeverityInfo    = 0
	osquerySeverityWarning = 1
	osquerySeverityError   = 2
)
