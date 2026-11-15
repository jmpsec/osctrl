package santa

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
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

var (
	// ErrRequestNotPending is returned when the request was already decided or expired.
	ErrRequestNotPending = errors.New("santa: request is not pending")
	// ErrRuleConflict is returned when a rule that does not allow the file
	// already exists for the same file and scope.
	ErrRuleConflict = errors.New("santa: a rule that does not allow this file already exists for this scope")
)

// Decision is an approver's answer to a pending request.
type Decision struct {
	Approve bool
	// Scope of the allow rule on approval: "node" (the requesting machine),
	// "tag" or "env". Ignored on denial.
	Scope string
	// Tag name for scope "tag"; ignored otherwise.
	ScopeValue string
	// Required on denial, optional on approval; at most MaxJustification characters.
	Reason string
	// The approver.
	By string
}

// DecideRequest approves or denies a pending request. An approval stores one
// BINARY allow rule for the file in the chosen scope, or reuses an allow rule
// that is already there, in the same transaction as the status change.
// Returns gorm.ErrRecordNotFound if the request is not in envID.
func (m *Manager) DecideRequest(envID, id uint, d Decision) (Request, error) {
	return m.decideIn(m.DB, envID, id, d)
}

// decideIn is DecideRequest on db, which may be the caller's transaction: gorm
// then nests this one in a savepoint.
func (m *Manager) decideIn(db *gorm.DB, envID, id uint, d Decision) (Request, error) {
	d.Reason = strings.TrimSpace(d.Reason)
	switch {
	case d.By == "":
		return Request{}, fmt.Errorf("%w: approver is required", ErrInvalidRequest)
	case utf8.RuneCountInString(d.Reason) > MaxJustification:
		return Request{}, fmt.Errorf("%w: reason is at most %d characters", ErrInvalidRequest, MaxJustification)
	case !d.Approve && d.Reason == "":
		return Request{}, fmt.Errorf("%w: a reason is required to deny", ErrInvalidRequest)
	}
	var req Request
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("environment_id = ? AND id = ?", envID, id).First(&req).Error; err != nil {
			return err
		}
		now := m.now()
		req.Status, req.DecidedBy, req.DecidedAt, req.Reason = RequestDenied, d.By, &now, d.Reason
		if d.Approve {
			rule := Rule{
				EnvironmentID: envID, Identifier: req.FileSHA256, RuleType: "BINARY", Policy: "ALLOWLIST",
				Scope: d.Scope, ScopeValue: d.ScopeValue, CreatedBy: d.By,
			}
			switch d.Scope {
			case "node":
				rule.ScopeValue = req.MachineID
			case "env":
				rule.ScopeValue = ""
			}
			if err := ValidateRule(&rule); err != nil {
				return err
			}
			rule, _, err := allowRule(tx, rule)
			if err != nil {
				return err
			}
			req.Status, req.RuleID = RequestApproved, rule.ID
		}
		// The status condition makes a second decision a no-op, so one request
		// never produces two rules.
		res := tx.Model(&Request{}).Where("id = ? AND status = ?", req.ID, RequestPending).Updates(map[string]any{
			"status": req.Status, "decided_by": req.DecidedBy, "decided_at": req.DecidedAt,
			"reason": req.Reason, "rule_id": req.RuleID, "updated_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrRequestNotPending
		}
		req.UpdatedAt = now
		return nil
	})
	return req, err
}

// allowRule stores a validated allow rule in tx, or returns the allow rule that
// is already there for the same file and scope (created is false). A rule that
// does not allow the file is ErrRuleConflict.
func allowRule(tx *gorm.DB, rule Rule) (_ Rule, created bool, err error) {
	// Looked up before the insert: a failed insert would abort the transaction.
	var existing []Rule
	if err := tx.Where("environment_id = ? AND rule_type = ? AND identifier = ? AND scope = ? AND scope_value = ?",
		rule.EnvironmentID, rule.RuleType, rule.Identifier, rule.Scope, rule.ScopeValue).Limit(1).Find(&existing).Error; err != nil {
		return rule, false, err
	}
	switch {
	case len(existing) == 0:
		return rule, true, tx.Create(&rule).Error
	case strings.HasPrefix(existing[0].Policy, "ALLOWLIST"):
		return existing[0], false, nil
	}
	return rule, false, ErrRuleConflict
}

// ExpireRequests marks pending requests created before olderThan as expired
// and returns how many.
func (m *Manager) ExpireRequests(olderThan time.Time) (int64, error) {
	res := m.DB.Model(&Request{}).Where("status = ? AND created_at < ?", RequestPending, olderThan).
		Updates(map[string]any{"status": RequestExpired, "updated_at": m.now()})
	return res.RowsAffected, res.Error
}
