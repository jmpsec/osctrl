package alerts

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// manager.go — persistence for alert rules, channels, and history.
//
// Follows the pkg/logsinks manager shape: AutoMigrate on construction,
// validate-before-write, soft errors via exported sentinel errors. The
// manager also owns building rule snapshots: LoadSnapshot reads all
// enabled rules and publishes a compiled RuleSet to a Store.

// Manager manages the alert_rules / alert_channels / alert_history
// tables.
type Manager struct {
	DB *gorm.DB
}

// NewManager initializes the manager and auto-migrates the three tables.
// AutoMigrate is production-impacting (it creates the tables on first
// boot) but additive: existing deployments gain three empty tables.
func NewManager(backend *gorm.DB) *Manager {
	m := &Manager{DB: backend}
	if err := backend.AutoMigrate(&AlertRule{}, &AlertChannel{}, &AlertHistory{}); err != nil {
		panic(fmt.Sprintf("Failed to AutoMigrate alert tables: %v", err))
	}
	return m
}

// ─────────────────────────────── rules ───────────────────────────────

// CreateRule validates and inserts a new rule. The rule-count cap per
// environment is enforced here.
func (m *Manager) CreateRule(rule AlertRule) (AlertRule, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	if err := ValidateRule(rule); err != nil {
		return AlertRule{}, err
	}
	if err := m.checkRuleCap(rule.EnvironmentID); err != nil {
		return AlertRule{}, err
	}
	rule.ChannelIDs = normalizeChannelIDs(rule.ChannelIDs)
	row := rule
	row.ID = 0
	if err := m.DB.Create(&row).Error; err != nil {
		if isDuplicate(err) {
			return AlertRule{}, ErrRuleExists
		}
		return AlertRule{}, fmt.Errorf("create alert rule: %w", err)
	}
	return row, nil
}

// UpdateRule replaces the mutable fields of an existing rule.
func (m *Manager) UpdateRule(id uint, rule AlertRule) (AlertRule, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	if err := ValidateRule(rule); err != nil {
		return AlertRule{}, err
	}
	row, err := m.GetRule(id)
	if err != nil {
		return AlertRule{}, err
	}
	rule.ChannelIDs = normalizeChannelIDs(rule.ChannelIDs)
	if err := m.DB.Model(&row).Updates(map[string]any{
		"name":             rule.Name,
		"source":           rule.Source,
		"match_type":       rule.MatchType,
		"match_field":      rule.MatchField,
		"match_value":      rule.MatchValue,
		"status_severity":  rule.StatusSeverity,
		"cooldown_minutes": rule.CooldownMinutes,
		"channel_ids":      rule.ChannelIDs,
		"enabled":          rule.Enabled,
		"info":             rule.Info,
	}).Error; err != nil {
		return AlertRule{}, fmt.Errorf("update alert rule: %w", err)
	}
	return m.GetRule(id)
}

// GetRule retrieves one rule by ID.
func (m *Manager) GetRule(id uint) (AlertRule, error) {
	var row AlertRule
	if err := m.DB.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AlertRule{}, ErrRuleNotFound
		}
		return AlertRule{}, err
	}
	return row, nil
}

// DeleteRule removes a rule by ID. History rows are not cascaded — they
// keep the RuleName snapshot for the audit trail.
func (m *Manager) DeleteRule(id uint) error {
	res := m.DB.Delete(&AlertRule{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// ListRules returns all rules, optionally scoped to one environment.
// envID nil = all environments; NoEnvironmentID = global rows only.
func (m *Manager) ListRules(envID *uint) ([]AlertRule, error) {
	q := m.DB.Order("environment_id ASC, name ASC")
	if envID != nil {
		q = q.Where("environment_id = ?", *envID)
	}
	var rows []AlertRule
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// checkRuleCap enforces MaxRulesPerEnv per environment.
func (m *Manager) checkRuleCap(envID uint) error {
	var count int64
	if err := m.DB.Model(&AlertRule{}).Where("environment_id = ?", envID).Count(&count).Error; err != nil {
		return err
	}
	if count >= MaxRulesPerEnv {
		return ErrTooManyRules
	}
	return nil
}

// normalizeChannelIDs canonicalizes the JSON array so "empty" is always
// "[]" and parse errors surface at validation time.
func normalizeChannelIDs(raw string) string {
	ids, err := decodeChannels(raw)
	if err != nil || ids == nil {
		return "[]"
	}
	return encodeChannels(ids)
}

// ─────────────────────────────── channels ───────────────────────────────

// CreateChannel inserts a new notification channel. Type and config are
// validated against the channel registry.
func (m *Manager) CreateChannel(ch AlertChannel) (AlertChannel, error) {
	ch.Name = strings.TrimSpace(ch.Name)
	if ch.Name == "" {
		return AlertChannel{}, errors.New("channel name is required")
	}
	if err := ValidateChannelConfig(ch.Type, ch.Config); err != nil {
		return AlertChannel{}, err
	}
	if ch.Config == "" {
		ch.Config = "{}"
	}
	row := ch
	row.ID = 0
	if err := m.DB.Create(&row).Error; err != nil {
		if isDuplicate(err) {
			return AlertChannel{}, ErrChannelExists
		}
		return AlertChannel{}, fmt.Errorf("create alert channel: %w", err)
	}
	return row, nil
}

// UpdateChannel replaces the mutable fields of a channel. Type and
// config are re-validated.
func (m *Manager) UpdateChannel(id uint, ch AlertChannel) (AlertChannel, error) {
	row, err := m.GetChannel(id)
	if err != nil {
		return AlertChannel{}, err
	}
	ch.Name = strings.TrimSpace(ch.Name)
	if ch.Name == "" {
		return AlertChannel{}, errors.New("channel name is required")
	}
	if err := ValidateChannelConfig(ch.Type, ch.Config); err != nil {
		return AlertChannel{}, err
	}
	if ch.Config == "" {
		ch.Config = "{}"
	}
	if err := m.DB.Model(&row).Updates(map[string]any{
		"name":    ch.Name,
		"type":    normalizeChannelType(ch.Type),
		"config":  ch.Config,
		"enabled": ch.Enabled,
		"info":    ch.Info,
	}).Error; err != nil {
		return AlertChannel{}, fmt.Errorf("update alert channel: %w", err)
	}
	return m.GetChannel(id)
}

// GetChannel retrieves one channel by ID.
func (m *Manager) GetChannel(id uint) (AlertChannel, error) {
	var row AlertChannel
	if err := m.DB.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AlertChannel{}, ErrChannelNotFound
		}
		return AlertChannel{}, err
	}
	return row, nil
}

// DeleteChannel removes a channel by ID. Rules referencing it keep the
// dangling ID in ChannelIDs; dispatch treats unknown channels as
// disabled and skips them.
func (m *Manager) DeleteChannel(id uint) error {
	res := m.DB.Delete(&AlertChannel{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrChannelNotFound
	}
	return nil
}

// ListChannels returns all channels, optionally env-scoped.
func (m *Manager) ListChannels(envID *uint) ([]AlertChannel, error) {
	q := m.DB.Order("environment_id ASC, name ASC")
	if envID != nil {
		q = q.Where("environment_id = ?", *envID)
	}
	var rows []AlertChannel
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ─────────────────────────────── history ───────────────────────────────

// RecordHistory appends one dispatched-alert row (dispatch worker only).
// Detail is bounded here as defense in depth — the matcher already
// truncates at hit time.
func (m *Manager) RecordHistory(h AlertHistory) error {
	if len(h.Detail) > detailMax {
		h.Detail = truncateDetail(h.Detail)
	}
	if err := m.DB.Create(&h).Error; err != nil {
		return fmt.Errorf("record alert history: %w", err)
	}
	return nil
}

// RecentHistory returns the newest history rows, capped.
func (m *Manager) RecentHistory(limit int) ([]AlertHistory, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows []AlertHistory
	if err := m.DB.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// PruneHistory removes rows older than the retention window. Called by a
// periodic sweep, never on the hot path.
func (m *Manager) PruneHistory(olderThan interface{}) (int64, error) {
	res := m.DB.Where("created_at < ?", olderThan).Delete(&AlertHistory{})
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// ─────────────────────────────── snapshot ───────────────────────────────

// LoadSnapshot reads all enabled rules, compiles them, and publishes a
// fresh RuleSet to the store. A rule that fails to compile (bad regex
// introduced by direct DB edit) is skipped with the error surfaced; it
// never blocks the rest of the ruleset.
func (m *Manager) LoadSnapshot(store *Store) error {
	var rules []AlertRule
	if err := m.DB.Where("enabled = ?", true).Find(&rules).Error; err != nil {
		return fmt.Errorf("load alert rules: %w", err)
	}
	rs := &RuleSet{}
	for _, rule := range rules {
		cr, err := CompileRule(rule)
		if err != nil {
			continue // skip invalid rule, keep the rest serving
		}
		switch rule.Source {
		case SourceResultLog:
			rs.result = append(rs.result, cr)
		case SourceStatusLog:
			rs.status = append(rs.status, cr)
		case SourceQueryLog:
			rs.query = append(rs.query, cr)
		default:
			// node_inactive / node_recovered rules are evaluated by the
			// sweep, not the log matcher; nothing to compile.
		}
	}
	store.Publish(rs)
	return nil
}

// ─────────────────────────────── shared helpers ───────────────────────────────

// isDuplicate reports whether err is a unique-constraint violation on
// the supported backends (PG / MySQL / SQLite).
func isDuplicate(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "duplicate entry") ||
		strings.Contains(msg, "unique constraint")
}
