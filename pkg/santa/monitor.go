package santa

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

// MaxMonitorHours is the longest temporary MONITOR mode, in hours.
const MaxMonitorHours = 24

var (
	// ErrUnknownMachine is returned when the machine has never synced in the environment.
	ErrUnknownMachine = errors.New("santa: machine has not synced with this environment")
	// ErrPermanentOverride is returned when the machine already has a permanent
	// node override, which a temporary one would replace and not restore.
	ErrPermanentOverride = errors.New("santa: the machine has a permanent mode override; change or delete it instead")
)

// GrantMonitor switches a machine that has synced in the environment to
// MONITOR for hours (1 to MaxMonitorHours), from now. It replaces a temporary
// override of the machine, never a permanent one. Clients pick it up at their
// next preflight and go back at the first preflight after it expires.
func (m *Manager) GrantMonitor(envID uint, machineID string, hours uint, by string) (ModeOverride, error) {
	return m.grantMonitorIn(m.DB, envID, machineID, hours, by)
}

func (m *Manager) grantMonitorIn(db *gorm.DB, envID uint, machineID string, hours uint, by string) (ModeOverride, error) {
	machineID = strings.ToUpper(strings.TrimSpace(machineID))
	switch {
	case !uuidRe.MatchString(machineID):
		return ModeOverride{}, fmt.Errorf("%w: node scope requires a UUID", ErrInvalidOverride)
	case hours < 1 || hours > MaxMonitorHours:
		return ModeOverride{}, fmt.Errorf("%w: temporary MONITOR mode lasts 1 to %d hours", ErrInvalidOverride, MaxMonitorHours)
	case by == "":
		return ModeOverride{}, fmt.Errorf("%w: granted by is required", ErrInvalidOverride)
	}
	var o ModeOverride
	err := db.Transaction(func(tx *gorm.DB) error {
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
		o = ModeOverride{EnvironmentID: envID, Scope: "node", ScopeValue: machineID, ClientMode: "MONITOR", CreatedBy: by, ExpiresAt: &expires}
		return upsertModeOverride(tx, &o)
	})
	return o, err
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
	case hours < 1 || hours > MaxMonitorHours:
		return req, false, fmt.Errorf("%w: hours must be 1 to %d", ErrInvalidRequest, MaxMonitorHours)
	case justification == "" || utf8.RuneCountInString(justification) > MaxJustification:
		return req, false, fmt.Errorf("%w: justification is required, at most %d characters", ErrInvalidRequest, MaxJustification)
	case requester == "":
		return req, false, fmt.Errorf("%w: requester is required", ErrInvalidRequest)
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
