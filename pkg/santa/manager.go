package santa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const maxPageSize = 500

// ErrRuleExists is returned by CreateRule for a duplicate rule.
var ErrRuleExists = errors.New("santa rule already exists")

// Manager provides persistence for Santa configs, rules, machines and events.
type Manager struct {
	DB  *gorm.DB
	now func() time.Time
}

// NewManager migrates the Santa tables and returns a Manager.
func NewManager(db *gorm.DB) (*Manager, error) {
	if err := Migrate(db); err != nil {
		return nil, err
	}
	return &Manager{DB: db, now: time.Now}, nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Config returns the environment config, or MONITOR defaults when none is stored.
func (m *Manager) Config(envID uint) (EnvConfig, error) {
	var rows []EnvConfig
	if err := m.DB.Where("environment_id = ?", envID).Limit(1).Find(&rows).Error; err != nil {
		return EnvConfig{}, err
	}
	if len(rows) == 0 {
		return EnvConfig{EnvironmentID: envID, ClientMode: "MONITOR", RemovableMedia: MediaAllow}, nil
	}
	return rows[0], nil
}

// SaveConfig validates and upserts the config by environment; TokenHash is never written.
func (m *Manager) SaveConfig(cfg EnvConfig) error {
	if err := ValidateConfig(&cfg); err != nil {
		return err
	}
	cfg.ID = 0
	cfg.TokenHash = ""
	return m.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "environment_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"client_mode", "batch_size", "enable_transitive_rules", "block_usb_mount",
			"removable_media", "removable_media_flags", "encrypted_removable_media", "encrypted_removable_media_flags", "updated_at"}),
	}).Create(&cfg).Error
}

// RotateToken issues a new sync token, stores only its hash and returns the plaintext once.
func (m *Manager) RotateToken(envID uint) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	cfg := EnvConfig{EnvironmentID: envID, ClientMode: "MONITOR", RemovableMedia: MediaAllow, TokenHash: hashToken(token)}
	err := m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "environment_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"token_hash", "updated_at"}),
	}).Create(&cfg).Error
	if err != nil {
		return "", err
	}
	return token, nil
}

// CheckToken reports whether presented matches the environment's sync token.
func (m *Manager) CheckToken(envID uint, presented string) bool {
	cfg, err := m.Config(envID)
	if err != nil || cfg.TokenHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cfg.TokenHash), []byte(hashToken(presented))) == 1
}

// Rules lists the environment's rules ordered by ID.
func (m *Manager) Rules(envID uint) ([]Rule, error) {
	var rules []Rule
	err := m.DB.Where("environment_id = ?", envID).Order("id").Find(&rules).Error
	return rules, err
}

// CreateRule validates and stores r; the unique index rejects duplicates.
func (m *Manager) CreateRule(r *Rule) error {
	if err := ValidateRule(r); err != nil {
		return err
	}
	err := m.DB.Create(r).Error
	if err == nil {
		return nil
	}
	// Portable duplicate detection: avoids matching driver-specific error strings.
	var n int64
	if cerr := m.DB.Model(&Rule{}).Where("environment_id = ? AND rule_type = ? AND identifier = ? AND scope = ? AND scope_value = ?",
		r.EnvironmentID, r.RuleType, r.Identifier, r.Scope, r.ScopeValue).Count(&n).Error; cerr == nil && n > 0 {
		return ErrRuleExists
	}
	return err
}

// UpdateRule validates r and replaces the user-settable fields of rule r.ID in
// r.EnvironmentID; CreatedBy is kept. Returns gorm.ErrRecordNotFound if the
// rule is not in that environment, ErrRuleExists if the edit duplicates
// another rule.
func (m *Manager) UpdateRule(r *Rule) error {
	if err := ValidateRule(r); err != nil {
		return err
	}
	var n int64
	if err := m.DB.Model(&Rule{}).Where("environment_id = ? AND rule_type = ? AND identifier = ? AND scope = ? AND scope_value = ? AND id <> ?",
		r.EnvironmentID, r.RuleType, r.Identifier, r.Scope, r.ScopeValue, r.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrRuleExists
	}
	r.UpdatedAt = m.now()
	// A map, so emptied fields (custom_msg, cel_expr) are written too.
	res := m.DB.Model(&Rule{}).Where("environment_id = ? AND id = ?", r.EnvironmentID, r.ID).
		Updates(map[string]any{
			"identifier": r.Identifier, "rule_type": r.RuleType, "policy": r.Policy, "cel_expr": r.CELExpr,
			"custom_msg": r.CustomMsg, "custom_url": r.CustomURL, "scope": r.Scope, "scope_value": r.ScopeValue,
			"updated_at": r.UpdatedAt,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Rule returns one rule, gorm.ErrRecordNotFound if it is not in envID.
func (m *Manager) Rule(envID, id uint) (Rule, error) {
	var r Rule
	err := m.DB.Where("environment_id = ? AND id = ?", envID, id).First(&r).Error
	return r, err
}

// DeleteRule removes a rule, returning gorm.ErrRecordNotFound if it is not in envID.
func (m *Manager) DeleteRule(envID, id uint) error {
	res := m.DB.Where("environment_id = ? AND id = ?", envID, id).Delete(&Rule{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ModeOverrides lists the environment's client mode overrides ordered by ID.
func (m *Manager) ModeOverrides(envID uint) ([]ModeOverride, error) {
	var os []ModeOverride
	err := m.DB.Where("environment_id = ?", envID).Order("id").Find(&os).Error
	return os, err
}

// SetModeOverride validates o and upserts it by (environment, scope, scope value),
// then reloads it so o carries the stored ID.
func (m *Manager) SetModeOverride(o *ModeOverride) error {
	if err := ValidateModeOverride(o); err != nil {
		return err
	}
	o.ID = 0
	if err := m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "environment_id"}, {Name: "scope"}, {Name: "scope_value"}},
		DoUpdates: clause.AssignmentColumns([]string{"client_mode", "created_by", "updated_at"}),
	}).Create(o).Error; err != nil {
		return err
	}
	return m.DB.Where("environment_id = ? AND scope = ? AND scope_value = ?", o.EnvironmentID, o.Scope, o.ScopeValue).First(o).Error
}

// DeleteModeOverride removes an override and returns it, or
// gorm.ErrRecordNotFound if it is not in envID.
func (m *Manager) DeleteModeOverride(envID, id uint) (ModeOverride, error) {
	var o ModeOverride
	if err := m.DB.Where("environment_id = ? AND id = ?", envID, id).First(&o).Error; err != nil {
		return o, err
	}
	return o, m.DB.Delete(&o).Error
}

// EffectiveMode returns the client mode for a node and where it comes from
// ("node", "tag" or "env"). A node override beats tag overrides, which beat the
// environment mode; when the node's tags disagree, LOCKDOWN wins.
func (m *Manager) EffectiveMode(envID uint, nodeUUID string, tags []string) (mode, source string, err error) {
	cfg, err := m.Config(envID)
	if err != nil {
		return "", "", err
	}
	overrides, err := m.ModeOverrides(envID)
	if err != nil {
		return "", "", err
	}
	mode, source = cfg.ClientMode, "env"
	for _, o := range overrides {
		switch {
		case o.Scope == "node" && strings.EqualFold(o.ScopeValue, nodeUUID):
			return o.ClientMode, "node", nil
		case o.Scope == "tag" && slices.Contains(tags, o.ScopeValue):
			if source != "tag" || o.ClientMode == "LOCKDOWN" {
				mode, source = o.ClientMode, "tag"
			}
		}
	}
	return mode, source, nil
}

// Machine returns one machine, gorm.ErrRecordNotFound if unknown.
func (m *Manager) Machine(envID uint, machineID string) (Machine, error) {
	var mc Machine
	err := m.DB.Where("environment_id = ? AND machine_id = ?", envID, machineID).First(&mc).Error
	return mc, err
}

// SaveMachine upserts a machine by (environment, machine ID).
func (m *Manager) SaveMachine(mc *Machine) error {
	return m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "environment_id"}, {Name: "machine_id"}},
		UpdateAll: true,
	}).Create(mc).Error
}

// Machines lists the environment's machines.
func (m *Manager) Machines(envID uint) ([]Machine, error) {
	var ms []Machine
	err := m.DB.Where("environment_id = ?", envID).Order("id").Find(&ms).Error
	return ms, err
}

// AddEvents batch-inserts events, stamping a zero CreatedAt with the current time.
func (m *Manager) AddEvents(evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	now := m.now()
	for i := range evs {
		if evs[i].CreatedAt.IsZero() {
			evs[i].CreatedAt = now
		}
	}
	return m.DB.CreateInBatches(&evs, 200).Error
}

// Events returns a newest-first page (1-based) and the total count.
func (m *Manager) Events(envID uint, page, pageSize int) ([]Event, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	q := m.DB.Model(&Event{}).Where("environment_id = ?", envID)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var evs []Event
	err := q.Order("created_at DESC, id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&evs).Error
	return evs, total, err
}

// PruneEvents deletes events created before olderThan and returns how many.
func (m *Manager) PruneEvents(olderThan time.Time) (int64, error) {
	res := m.DB.Where("created_at < ?", olderThan).Delete(&Event{})
	return res.RowsAffected, res.Error
}
