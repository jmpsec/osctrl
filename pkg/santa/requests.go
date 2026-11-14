package santa

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxJustification is the longest justification accepted, in characters.
	MaxJustification = 1000
	// MaxPendingRequests caps one requester's pending requests in an environment.
	MaxPendingRequests = 20
)

var (
	// ErrInvalidRequest wraps every CreateRequest input failure.
	ErrInvalidRequest = errors.New("invalid santa request")
	// ErrNoBlockedEvent is returned when no block of the file on the machine is known.
	ErrNoBlockedEvent = errors.New("santa: no blocked execution for this file and machine")
	// ErrTooManyRequests is returned when the requester is at MaxPendingRequests.
	ErrTooManyRequests = errors.New("santa: too many pending requests")
)

// CreateRequest stores a pending approval request for a file blocked on a
// machine. The block must be a stored event: it is what links the request to
// something that happened. A pending request for the same file and machine is
// returned instead of a second one (created is false), whoever made it.
func (m *Manager) CreateRequest(envID uint, machineID, sha256, requester, justification string) (req Request, created bool, err error) {
	machineID = strings.ToUpper(strings.TrimSpace(machineID))
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	justification = strings.TrimSpace(justification)
	switch {
	case !uuidRe.MatchString(machineID):
		return req, false, fmt.Errorf("%w: machine_id must be a UUID", ErrInvalidRequest)
	case !hex64.MatchString(sha256):
		return req, false, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	case justification == "" || utf8.RuneCountInString(justification) > MaxJustification:
		return req, false, fmt.Errorf("%w: justification is required, at most %d characters", ErrInvalidRequest, MaxJustification)
	case requester == "":
		return req, false, fmt.Errorf("%w: requester is required", ErrInvalidRequest)
	}
	evs, _, err := m.Events(envID, 1, 1, EventFilter{MachineID: machineID, Decision: "BLOCK", SHA256: sha256})
	if err != nil {
		return req, false, err
	}
	if len(evs) == 0 {
		return req, false, ErrNoBlockedEvent
	}
	// ponytail: check-then-insert, two simultaneous submissions can both insert.
	// The duplicate is one extra pending row; add a unique key if it matters.
	var pending []Request
	if err := m.DB.Where("environment_id = ? AND machine_id = ? AND file_sha256 = ? AND status = ?",
		envID, machineID, sha256, RequestPending).Order("id").Limit(1).Find(&pending).Error; err != nil {
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
	ev := evs[0]
	req = Request{
		EnvironmentID: envID, MachineID: machineID, FileSHA256: sha256, EventID: ev.ID,
		FileName: ev.FileName, FilePath: ev.FilePath, SigningID: ev.SigningID, TeamID: ev.TeamID, ExecutingUser: ev.ExecutingUser,
		Requester: requester, Justification: justification, Status: RequestPending,
	}
	return req, true, m.DB.Create(&req).Error
}

// Requests lists the environment's requests, newest first, at most maxPageSize.
// An empty status lists every status; an empty requester lists every requester.
func (m *Manager) Requests(envID uint, status, requester string) ([]Request, error) {
	q := m.DB.Where("environment_id = ?", envID)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if requester != "" {
		q = q.Where("requester = ?", requester)
	}
	var reqs []Request
	err := q.Order("id DESC").Limit(maxPageSize).Find(&reqs).Error
	return reqs, err
}

// ExpireRequests marks pending requests created before olderThan as expired
// and returns how many.
func (m *Manager) ExpireRequests(olderThan time.Time) (int64, error) {
	res := m.DB.Model(&Request{}).Where("status = ? AND created_at < ?", RequestPending, olderThan).
		Updates(map[string]any{"status": RequestExpired, "updated_at": m.now()})
	return res.RowsAffected, res.Error
}
