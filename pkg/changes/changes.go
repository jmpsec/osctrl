// Package changes holds risky admin actions for a second admin's approval.
//
// A gated handler calls Gate with the exact request it received. The first time,
// Gate stores a pending change and the handler answers 202. Another admin of the
// environment approves it; the requester then sends the same request again
// (same method, path and body), Gate consumes the approval and the handler runs
// as usual, with its own validation and audit. An approval is for one use, by
// the requester, before the change expires.
package changes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusApplied  = "applied"
	// StatusExpired is never stored: a pending or approved change past ExpiresAt.
	StatusExpired = "expired"

	// TTL is how long a change can wait for approval and then for its use.
	TTL = 24 * time.Hour
	// maxList caps List.
	maxList = 200
)

var (
	// ErrSelfApproval is returned when the requester approves their own change.
	ErrSelfApproval = errors.New("changes: another admin must approve this change")
	// ErrNotPending is returned for a decision on a change that is not pending.
	ErrNotPending = errors.New("changes: change is not pending")
)

// Change is a held admin action.
type Change struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	EnvironmentID uint      `gorm:"index" json:"-"`
	// What the change does, as it appears in the audit log
	Action string `gorm:"type:varchar(512)" json:"action"`
	Method string `gorm:"type:varchar(8)" json:"method"`
	Path   string `gorm:"type:varchar(512)" json:"path"`
	// The request body, sent again unchanged to apply the change
	Body        string     `gorm:"type:text" json:"body"`
	Digest      string     `gorm:"type:varchar(64);index" json:"-"`
	RequestedBy string     `gorm:"type:varchar(255)" json:"requested_by"`
	Status      string     `gorm:"type:varchar(16)" json:"status"`
	DecidedBy   string     `gorm:"type:varchar(255)" json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
}

// TableName keeps the table name explicit.
func (Change) TableName() string { return "pending_changes" }

// Manager stores changes.
type Manager struct {
	DB  *gorm.DB
	now func() time.Time
}

// NewManager migrates the table.
func NewManager(db *gorm.DB) (*Manager, error) {
	if err := db.AutoMigrate(&Change{}); err != nil {
		return nil, err
	}
	return &Manager{DB: db, now: time.Now}, nil
}

func digest(method, path string, body []byte) string {
	s := sha256.New()
	s.Write([]byte(method + " " + path + "\n"))
	s.Write(body)
	return hex.EncodeToString(s.Sum(nil))
}

// Gate returns the change for this exact request by user. If an approval for it
// is waiting, it is consumed and the change comes back as applied: the caller
// runs the action. Otherwise the change is pending (created reports a new one)
// and the caller must not run the action.
func (m *Manager) Gate(envID uint, user, action, method, path string, body []byte) (c Change, created bool, err error) {
	d := digest(method, path, body)
	now := m.now()
	var found []Change
	if err := m.DB.Where("environment_id = ? AND requested_by = ? AND digest = ? AND status IN ? AND expires_at > ?",
		envID, user, d, []string{StatusPending, StatusApproved}, now).Order("id").Find(&found).Error; err != nil {
		return c, false, err
	}
	for _, f := range found {
		if f.Status != StatusApproved {
			continue
		}
		// The status condition makes the use single even under concurrency.
		res := m.DB.Model(&Change{}).Where("id = ? AND status = ?", f.ID, StatusApproved).Update("status", StatusApplied)
		if res.Error != nil {
			return c, false, res.Error
		}
		if res.RowsAffected == 1 {
			f.Status = StatusApplied
			return f, false, nil
		}
	}
	for _, f := range found {
		if f.Status == StatusPending {
			return f, false, nil
		}
	}
	c = Change{
		EnvironmentID: envID, Action: action, Method: method, Path: path, Body: string(body), Digest: d,
		RequestedBy: user, Status: StatusPending, ExpiresAt: now.Add(TTL),
	}
	return c, true, m.DB.Create(&c).Error
}

// List returns the environment's changes, newest first.
func (m *Manager) List(envID uint) ([]Change, error) {
	var cs []Change
	if err := m.DB.Where("environment_id = ?", envID).Order("id DESC").Limit(maxList).Find(&cs).Error; err != nil {
		return nil, err
	}
	now := m.now()
	for i := range cs {
		cs[i].expire(now)
	}
	return cs, nil
}

func (c *Change) expire(now time.Time) {
	if (c.Status == StatusPending || c.Status == StatusApproved) && !c.ExpiresAt.After(now) {
		c.Status = StatusExpired
	}
}

// Decide approves or denies a pending change. Only someone other than the
// requester can approve; the requester can deny (withdraw) their own.
// Returns gorm.ErrRecordNotFound if the change is not in envID.
func (m *Manager) Decide(envID, id uint, by string, approve bool) (Change, error) {
	var c Change
	if err := m.DB.Where("environment_id = ? AND id = ?", envID, id).First(&c).Error; err != nil {
		return c, err
	}
	if approve && c.RequestedBy == by {
		return c, ErrSelfApproval
	}
	now := m.now()
	status := StatusDenied
	if approve {
		status = StatusApproved
	}
	res := m.DB.Model(&Change{}).Where("id = ? AND status = ? AND expires_at > ?", id, StatusPending, now).
		Updates(map[string]any{"status": status, "decided_by": by, "decided_at": now})
	if res.Error != nil {
		return c, res.Error
	}
	if res.RowsAffected != 1 {
		return c, ErrNotPending
	}
	c.Status, c.DecidedBy, c.DecidedAt = status, by, &now
	return c, nil
}

// Prune deletes changes created before olderThan.
func (m *Manager) Prune(olderThan time.Time) (int64, error) {
	res := m.DB.Where("created_at < ?", olderThan).Delete(&Change{})
	return res.RowsAffected, res.Error
}
