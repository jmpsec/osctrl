package santa

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

// MaxMonitorHours is the longest temporary MONITOR mode, in hours. An
// environment can lower it with EnvConfig.MaxMonitorHours.
const MaxMonitorHours = 24

var (
	// ErrUnknownMachine is returned when the machine has never synced in the environment.
	ErrUnknownMachine = errors.New("santa: machine has not synced with this environment")
	// ErrPermanentOverride is returned when the machine already has a permanent
	// node override, which a temporary one would replace and not restore.
	ErrPermanentOverride = errors.New("santa: the machine has a permanent mode override; change or delete it instead")
)

// monitorLimit is the longest temporary MONITOR mode in the environment, in
// hours, read on db so it works inside a transaction.
func monitorLimit(db *gorm.DB, envID uint) (uint, error) {
	var cfgs []EnvConfig
	if err := db.Select("max_monitor_hours").Where("environment_id = ?", envID).Limit(1).Find(&cfgs).Error; err != nil {
		return 0, err
	}
	if len(cfgs) == 0 || cfgs[0].MaxMonitorHours == 0 {
		return MaxMonitorHours, nil
	}
	return uint(cfgs[0].MaxMonitorHours), nil
}

// GrantMonitor switches a machine that has synced in the environment to
// MONITOR for hours (1 to the environment's maximum), from now. It replaces a temporary
// override of the machine, never a permanent one. Clients pick it up at their
// next preflight and go back at the first preflight after it expires.
func (m *Manager) GrantMonitor(envID uint, machineID string, hours uint, by string) (ModeOverride, error) {
	return m.grantMonitorIn(m.DB, envID, machineID, hours, by, "")
}

// grantMonitorIn is GrantMonitor on db for the request of requester, if any.
func (m *Manager) grantMonitorIn(db *gorm.DB, envID uint, machineID string, hours uint, by, requester string) (ModeOverride, error) {
	machineID = strings.ToUpper(strings.TrimSpace(machineID))
	limit, err := monitorLimit(db, envID)
	if err != nil {
		return ModeOverride{}, err
	}
	switch {
	case !uuidRe.MatchString(machineID):
		return ModeOverride{}, fmt.Errorf("%w: node scope requires a UUID", ErrInvalidOverride)
	case hours < 1 || hours > limit:
		return ModeOverride{}, fmt.Errorf("%w: temporary MONITOR mode lasts 1 to %d hours", ErrInvalidOverride, limit)
	case by == "":
		return ModeOverride{}, fmt.Errorf("%w: granted by is required", ErrInvalidOverride)
	}
	var o ModeOverride
	err = db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&Machine{}).Where("environment_id = ? AND machine_id = ?", envID, machineID).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return ErrUnknownMachine
		}
		var existing []ModeOverride
		if err := tx.Where("environment_id = ? AND scope = ? AND scope_value = ?", envID, "node", machineID).
			Limit(1).Find(&existing).Error; err != nil {
			return err
		}
		if len(existing) > 0 && existing[0].ExpiresAt == nil {
			return ErrPermanentOverride
		}
		expires := m.now().Add(time.Duration(hours) * time.Hour)
		o = ModeOverride{EnvironmentID: envID, Scope: "node", ScopeValue: machineID, ClientMode: "MONITOR", CreatedBy: by, Requester: requester, ExpiresAt: &expires}
		return upsertModeOverride(tx, &o)
	})
	return o, err
}

// ExtendMonitor moves the expiry of the unexpired temporary override id in envID
// hours later. The new expiry can be at most the environment's maximum from now. It
// returns gorm.ErrRecordNotFound when there is no such override, and
// ErrInvalidOverride for a permanent one or a refused duration.
func (m *Manager) ExtendMonitor(envID, id, hours uint) (ModeOverride, error) {
	var o ModeOverride
	limit, err := monitorLimit(m.DB, envID)
	if err != nil {
		return o, err
	}
	now := m.now()
	if err := m.DB.Where("environment_id = ? AND id = ? AND (expires_at IS NULL OR expires_at > ?)", envID, id, now).First(&o).Error; err != nil {
		return o, err
	}
	if o.ExpiresAt == nil {
		return o, fmt.Errorf("%w: only a temporary override can be extended", ErrInvalidOverride)
	}
	expires := o.ExpiresAt.Add(time.Duration(hours) * time.Hour)
	if hours < 1 || expires.Sub(now) > time.Duration(limit)*time.Hour {
		return o, fmt.Errorf("%w: temporary MONITOR mode can end at most %d hours from now", ErrInvalidOverride, limit)
	}
	// The old expiry in the condition loses to a concurrent change: not found.
	res := m.DB.Model(&ModeOverride{}).Where("id = ? AND expires_at = ?", o.ID, *o.ExpiresAt).
		Updates(map[string]any{"expires_at": expires, "updated_at": now})
	if res.Error != nil {
		return o, res.Error
	}
	if res.RowsAffected == 0 {
		return o, gorm.ErrRecordNotFound
	}
	o.ExpiresAt, o.UpdatedAt = &expires, now
	return o, nil
}

// ExpireModeOverrides deletes temporary overrides that expired at or before
// now and returns them. ModeOverrides already leaves them out, so this only
// tidies up and gives the caller something to audit; when two processes race,
// each override is returned by one of them.
func (m *Manager) ExpireModeOverrides(now time.Time) ([]ModeOverride, error) {
	var due []ModeOverride
	if err := m.DB.Where("expires_at IS NOT NULL AND expires_at <= ?", now).Find(&due).Error; err != nil {
		return nil, err
	}
	var out []ModeOverride
	for _, o := range due {
		// The expiry condition keeps an override renewed since the read.
		res := m.DB.Where("id = ? AND expires_at <= ?", o.ID, now).Delete(&ModeOverride{})
		if res.Error != nil {
			return out, res.Error
		}
		if res.RowsAffected > 0 {
			out = append(out, o)
		}
	}
	return out, nil
}

// CreateMonitorRequest stores a pending request for hours of MONITOR mode on a
// machine that has synced in the environment. A pending MONITOR request for the
// same machine is returned instead of a second one (created is false).
func (m *Manager) CreateMonitorRequest(envID uint, machineID, requester, justification string, hours uint) (req Request, created bool, err error) {
	machineID = strings.ToUpper(strings.TrimSpace(machineID))
	justification = strings.TrimSpace(justification)
	switch {
	case !uuidRe.MatchString(machineID):
		return req, false, fmt.Errorf("%w: machine_id must be a UUID", ErrInvalidRequest)
	case hours < 1:
		return req, false, fmt.Errorf("%w: hours must be at least 1", ErrInvalidRequest)
	case justification == "" || utf8.RuneCountInString(justification) > MaxJustification:
		return req, false, fmt.Errorf("%w: justification is required, at most %d characters", ErrInvalidRequest, MaxJustification)
	case requester == "":
		return req, false, fmt.Errorf("%w: requester is required", ErrInvalidRequest)
	}
	if limit, err := monitorLimit(m.DB, envID); err != nil {
		return req, false, err
	} else if hours > limit {
		return req, false, fmt.Errorf("%w: hours must be 1 to %d", ErrInvalidRequest, limit)
	}
	if _, err := m.Machine(envID, machineID); errors.Is(err, gorm.ErrRecordNotFound) {
		return req, false, ErrUnknownMachine
	} else if err != nil {
		return req, false, err
	}
	// ponytail: check-then-insert like CreateRequest; a simultaneous duplicate is one extra pending row.
	var pending []Request
	if err := m.DB.Where("environment_id = ? AND machine_id = ? AND kind = ? AND status = ?",
		envID, machineID, RequestKindMonitor, RequestPending).Order("id").Limit(1).Find(&pending).Error; err != nil {
		return req, false, err
	}
	if len(pending) > 0 {
		return pending[0], false, nil
	}
	var n int64
	if err := m.DB.Model(&Request{}).Where("environment_id = ? AND requester = ? AND status = ?",
		envID, requester, RequestPending).Count(&n).Error; err != nil {
		return req, false, err
	}
	if n >= MaxPendingRequests {
		return req, false, ErrTooManyRequests
	}
	req = Request{
		EnvironmentID: envID, MachineID: machineID, Kind: RequestKindMonitor, MonitorHours: hours,
		Requester: requester, Justification: justification, Status: RequestPending,
	}
	return req, true, m.DB.Create(&req).Error
}
