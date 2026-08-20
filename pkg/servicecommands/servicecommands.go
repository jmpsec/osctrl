// Package servicecommands stores small, allowlisted service control requests.
package servicecommands

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	ActionRestart = "restart"
	// ActionPersistConfig asks a service to write its DB-edited config
	// sections back to its own YAML file. Unlike a restart it does not
	// change what the running process is using — only what is on disk.
	ActionPersistConfig = "persist-config"
	// ActionReloadLogSinks asks osctrl-tls to rebuild its per-environment
	// log sink exporter map from the log_sinks table and swap it in
	// without restarting. In-flight logs to the old sinks may be dropped
	// during the swap; the old sinks are closed immediately after the
	// new set is live.
	ActionReloadLogSinks = "reload-log-sinks"
	// ActionReloadAuthProviders asks osctrl-api to rebuild its
	// auth provider registry from the auth_providers table and swap
	// it in without restarting. Users mid-login may see a transient
	// error and can retry.
	ActionReloadAuthProviders = "reload-auth-providers"

	StatusPending   = "pending"
	StatusConsumed  = "consumed"
	StatusRecovered = "recovered"
	StatusExpired   = "expired"
)

var (
	ErrInvalidTarget = errors.New("invalid service command target")
	ErrInvalidAction = errors.New("invalid service command action")
)

// validActions is the allowlist of commands a service will act on. Anything
// not listed here is rejected at request time, so a row in the table can
// never name an action the consumer does not recognise.
var validActions = map[string]struct{}{
	ActionRestart:             {},
	ActionPersistConfig:       {},
	ActionReloadLogSinks:      {},
	ActionReloadAuthProviders: {},
}

// ServiceCommand is a one-shot control request for another osctrl service.
type ServiceCommand struct {
	gorm.Model
	CommandID     string `gorm:"uniqueIndex"`
	TargetService string `gorm:"index:idx_service_commands_pending"`
	Action        string `gorm:"index:idx_service_commands_pending"`
	RequestedBy   string
	RequestedFrom string
	ConsumedAt    *time.Time `gorm:"index:idx_service_commands_pending"`
	ConsumedBy    string
	RecoveredAt   *time.Time
	RecoveredBy   string
	ExpiresAt     time.Time `gorm:"index:idx_service_commands_pending"`
}

// Status derives the operator-facing command status.
func (c ServiceCommand) Status(now time.Time) string {
	if c.RecoveredAt != nil {
		return StatusRecovered
	}
	if c.ConsumedAt != nil {
		return StatusConsumed
	}
	if !c.ExpiresAt.After(now) {
		return StatusExpired
	}
	return StatusPending
}

// Manager manages service_commands.
type Manager struct {
	DB *gorm.DB
}

func NewManager(db *gorm.DB) *Manager {
	m := &Manager{DB: db}
	if err := db.AutoMigrate(&ServiceCommand{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (service_commands): %v", err)
	}
	return m
}

func (m *Manager) RequestRestart(targetService, requestedBy, requestedFrom string, ttl time.Duration) (ServiceCommand, error) {
	return m.Request(targetService, ActionRestart, requestedBy, requestedFrom, ttl)
}

// Request enqueues a one-shot command for a service to consume on its next
// poll.
func (m *Manager) Request(targetService, action, requestedBy, requestedFrom string, ttl time.Duration) (ServiceCommand, error) {
	if targetService != config.ServiceTLS {
		return ServiceCommand{}, ErrInvalidTarget
	}
	if _, ok := validActions[action]; !ok {
		return ServiceCommand{}, ErrInvalidAction
	}
	if ttl <= 0 {
		return ServiceCommand{}, fmt.Errorf("ttl must be positive")
	}
	commandID, err := newCommandID()
	if err != nil {
		return ServiceCommand{}, err
	}
	cmd := ServiceCommand{
		CommandID:     commandID,
		TargetService: targetService,
		Action:        action,
		RequestedBy:   requestedBy,
		RequestedFrom: requestedFrom,
		ExpiresAt:     time.Now().Add(ttl),
	}
	if err := m.DB.Create(&cmd).Error; err != nil {
		return ServiceCommand{}, err
	}
	return cmd, nil
}

func (m *Manager) Get(commandID string) (ServiceCommand, error) {
	var cmd ServiceCommand
	if err := m.DB.Where("command_id = ?", commandID).First(&cmd).Error; err != nil {
		return ServiceCommand{}, err
	}
	return cmd, nil
}

// ConsumeNext claims the oldest pending command for the service, whatever its
// action. The caller dispatches on cmd.Action — actions are allowlisted at
// request time, so anything returned here is one the consumer knows.
func (m *Manager) ConsumeNext(targetService, consumedBy string, now time.Time) (ServiceCommand, bool, error) {
	if targetService != config.ServiceTLS {
		return ServiceCommand{}, false, ErrInvalidTarget
	}
	var consumed ServiceCommand
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var cmd ServiceCommand
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("target_service = ? AND consumed_at IS NULL AND expires_at > ?", targetService, now).
			Order("created_at ASC").
			Limit(1).
			Find(&cmd).Error
		if err != nil {
			return err
		}
		if cmd.ID == 0 {
			return nil
		}
		res := tx.Model(&ServiceCommand{}).
			Where("id = ? AND consumed_at IS NULL AND expires_at > ?", cmd.ID, now).
			Updates(map[string]any{
				"consumed_at": &now,
				"consumed_by": consumedBy,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		consumed = cmd
		consumed.ConsumedAt = &now
		consumed.ConsumedBy = consumedBy
		return nil
	})
	if err != nil {
		return ServiceCommand{}, false, err
	}
	return consumed, consumed.ID != 0, nil
}

func (m *Manager) MarkRecovered(targetService, recoveredBy string, now time.Time) (int64, error) {
	if targetService != config.ServiceTLS {
		return 0, ErrInvalidTarget
	}
	res := m.DB.Model(&ServiceCommand{}).
		Where("target_service = ? AND action = ? AND consumed_at IS NOT NULL AND recovered_at IS NULL", targetService, ActionRestart).
		Updates(map[string]any{
			"recovered_at": &now,
			"recovered_by": recoveredBy,
		})
	return res.RowsAffected, res.Error
}

func newCommandID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
