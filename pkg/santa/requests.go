package santa

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	if err := q.Order("id DESC").Limit(maxPageSize).Find(&reqs).Error; err != nil {
		return nil, err
	}
	return reqs, m.attach(reqs)
}

// attach fills the fields of reqs that are not stored.
func (m *Manager) attach(reqs []Request) error {
	if err := m.attachRisk(reqs); err != nil {
		return err
	}
	return m.attachEvents(reqs)
}

// attachEvents fills the leaf certificate and the bundle binary count of file
// requests from their blocked events, for the rule types an approval can use.
func (m *Manager) attachEvents(reqs []Request) error {
	var ids []uint
	for _, r := range reqs {
		if r.Kind != RequestKindMonitor && r.EventID != 0 {
			ids = append(ids, r.EventID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var evs []Event
	if err := m.DB.Select("id", "bundle_hash", "signing_chain").Where("id IN ?", ids).Find(&evs).Error; err != nil {
		return err
	}
	byID := map[uint]Event{}
	var hashes []string
	for _, e := range evs {
		byID[e.ID] = e
		if e.BundleHash != "" {
			hashes = append(hashes, e.BundleHash)
		}
	}
	counts := map[string]int{}
	if len(hashes) > 0 {
		var rows []struct {
			BundleHash string
			N          int
		}
		if err := m.DB.Model(&Event{}).Select("bundle_hash, COUNT(DISTINCT file_sha256) AS n").
			Where("environment_id = ? AND decision = ? AND bundle_hash IN ?", reqs[0].EnvironmentID, DecisionBundleBinary, hashes).
			Group("bundle_hash").Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			counts[r.BundleHash] = r.N
		}
	}
	for i := range reqs {
		e, ok := byID[reqs[i].EventID]
		if !ok || reqs[i].Kind == RequestKindMonitor {
			continue
		}
		if len(e.SigningChain) > 0 {
			reqs[i].CertSHA256 = e.SigningChain[0].SHA256
		}
		reqs[i].BundleBinaries = counts[e.BundleHash]
	}
	return nil
}

var (
	// ErrRequestNotPending is returned when the request was already decided or expired.
	ErrRequestNotPending = errors.New("santa: request is not pending")
	// ErrRuleConflict is returned when a rule that does not allow the file
	// already exists for the same file and scope.
	ErrRuleConflict = errors.New("santa: a rule that does not allow this file already exists for this scope")
	// ErrSelfApproval is returned when, with RequireSecondAdmin on, an admin
	// approves their own request for MONITOR or an environment-wide rule.
	ErrSelfApproval = errors.New("santa: another admin must approve your own request")
	// ErrOwnRequest is returned when an approver who is not an environment
	// admin approves their own request.
	ErrOwnRequest = errors.New("santa: approvers cannot approve their own request")
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
	// Approve although a risk check flagged the file; needs a reason.
	Override bool
	// By is an approver, not an environment admin: never their own request.
	NotOwn bool
	// Type of the allow rule on approval, with the identifier from the request
	// and its blocked event: "" or BINARY (the file), SIGNINGID, TEAMID or
	// CERTIFICATE (the leaf certificate). Ignored for MONITOR requests.
	RuleType string
	// With BINARY, also allow every binary the client uploaded for the file's bundle.
	Bundle bool
	// Aggregated risk verdict, set by riskForDecision before the transaction.
	risk string
}

// ErrOverrideReason is returned for a risk override without a reason.
var ErrOverrideReason = errors.New("santa: overriding a flagged risk verdict needs a reason")

// DecideRequest approves or denies a pending request. An approval stores one
// BINARY allow rule for the file in the chosen scope, or reuses an allow rule
// that is already there, in the same transaction as the status change.
// Returns gorm.ErrRecordNotFound if the request is not in envID.
func (m *Manager) DecideRequest(envID, id uint, d Decision) (Request, error) {
	if err := m.riskForDecision(m.DB, envID, id, &d); err != nil {
		return Request{}, err
	}
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
		if d.Approve && d.NotOwn && strings.EqualFold(req.Requester, d.By) {
			return ErrOwnRequest
		}
		// An admin's own request for MONITOR or an environment-wide rule is one
		// person loosening enforcement, the change a second admin must approve.
		if d.Approve && req.Requester == d.By && (req.Kind == RequestKindMonitor || d.Scope == "env") {
			var n int64
			if err := tx.Model(&EnvConfig{}).Where("environment_id = ? AND require_second_admin = ?", envID, true).Count(&n).Error; err != nil {
				return err
			}
			if n > 0 {
				return ErrSelfApproval
			}
		}
		now := m.now()
		req.Status, req.DecidedBy, req.DecidedAt, req.Reason = RequestDenied, d.By, &now, d.Reason
		switch {
		case d.Approve && req.Kind == RequestKindMonitor:
			// The hours run from the approval, not from the request.
			if _, err := m.grantMonitorIn(tx, envID, req.MachineID, req.MonitorHours, d.By, req.Requester); err != nil {
				return err
			}
			req.Status = RequestApproved
		case d.Approve:
			// A failed check is shown to the approver but does not stop them;
			// a flagged file needs an explicit, reasoned override.
			if d.risk == RiskFlagged {
				switch {
				case !d.Override:
					return ErrRiskFlagged
				case d.Reason == "":
					return ErrOverrideReason
				}
				req.RiskOverride = true
			}
			ruleType, ids, err := approvalIdentifiers(tx, req, d)
			if err != nil {
				return err
			}
			for i, id := range ids {
				rule := Rule{
					EnvironmentID: envID, Identifier: id, RuleType: ruleType, Policy: "ALLOWLIST",
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
				// The rule of the file itself is the request's rule.
				if i == 0 {
					req.RuleID = rule.ID
				}
			}
			req.Status, req.RuleType = RequestApproved, ruleType
		}
		// The status condition makes a second decision a no-op, so one request
		// never produces two rules.
		res := tx.Model(&Request{}).Where("id = ? AND status = ?", req.ID, RequestPending).Updates(map[string]any{
			"status": req.Status, "decided_by": req.DecidedBy, "decided_at": req.DecidedAt,
			"reason": req.Reason, "rule_id": req.RuleID, "rule_type": req.RuleType, "risk_override": req.RiskOverride, "updated_at": now,
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

// MaxBundleRules caps the rules one bundle approval creates.
const MaxBundleRules = 500

// approvalIdentifiers returns the rule type and identifiers an approval of req
// allows, the file's first. They come from the request and its blocked event,
// never from the approver.
func approvalIdentifiers(tx *gorm.DB, req Request, d Decision) (string, []string, error) {
	ruleType := d.RuleType
	if ruleType == "" {
		ruleType = "BINARY"
	}
	if d.Bundle && ruleType != "BINARY" {
		return "", nil, fmt.Errorf("%w: a bundle approval creates BINARY rules", ErrInvalidRequest)
	}
	var ev Event
	if ruleType == "CERTIFICATE" || d.Bundle {
		if err := tx.Where("environment_id = ? AND id = ?", req.EnvironmentID, req.EventID).First(&ev).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "", nil, fmt.Errorf("%w: the blocked event of the request is gone", ErrInvalidRequest)
			}
			return "", nil, err
		}
	}
	switch ruleType {
	case "BINARY":
		ids := []string{strings.ToLower(req.FileSHA256)}
		if !d.Bundle {
			return ruleType, ids, nil
		}
		if ev.BundleHash == "" {
			return "", nil, fmt.Errorf("%w: the file is not in a bundle the client hashed", ErrInvalidRequest)
		}
		var shas []string
		if err := tx.Model(&Event{}).Where("environment_id = ? AND decision = ? AND bundle_hash = ?", req.EnvironmentID, DecisionBundleBinary, ev.BundleHash).
			Distinct().Order("file_sha256").Limit(MaxBundleRules+1).Pluck("file_sha256", &shas).Error; err != nil {
			return "", nil, err
		}
		for _, s := range shas {
			// Clients report these; one that is not a hash is skipped, not trusted.
			if s = strings.ToLower(s); hex64.MatchString(s) && !slices.Contains(ids, s) {
				ids = append(ids, s)
			}
		}
		switch {
		case len(ids) == 1:
			return "", nil, fmt.Errorf("%w: no other binaries of the bundle were uploaded", ErrInvalidRequest)
		case len(ids) > MaxBundleRules:
			return "", nil, fmt.Errorf("%w: the bundle has more than %d binaries", ErrInvalidRequest, MaxBundleRules)
		}
		return ruleType, ids, nil
	case "TEAMID":
		if req.TeamID == "" {
			return "", nil, fmt.Errorf("%w: the file has no team ID", ErrInvalidRequest)
		}
		return ruleType, []string{req.TeamID}, nil
	case "SIGNINGID":
		sid := req.SigningID
		if sid != "" && !strings.Contains(sid, ":") && req.TeamID != "" {
			sid = req.TeamID + ":" + sid
		}
		if sid == "" {
			return "", nil, fmt.Errorf("%w: the file has no signing ID", ErrInvalidRequest)
		}
		return ruleType, []string{sid}, nil
	case "CERTIFICATE":
		if len(ev.SigningChain) == 0 {
			return "", nil, fmt.Errorf("%w: the client reported no signing certificate", ErrInvalidRequest)
		}
		return ruleType, []string{ev.SigningChain[0].SHA256}, nil
	}
	return "", nil, fmt.Errorf("%w: unknown rule type %q", ErrInvalidRequest, ruleType)
}

// allowRule stores a validated allow rule in tx, or returns the allow rule that
// is already there for the same file and scope (created is false). A rule that
// does not allow the file is ErrRuleConflict.
func allowRule(tx *gorm.DB, rule Rule) (_ Rule, created bool, err error) {
	// Insert first and skip on the unique key, so a vote or approval that
	// created the same rule a moment earlier is not an error (#1214).
	ins := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rule)
	if ins.Error != nil || ins.RowsAffected > 0 {
		return rule, ins.Error == nil, ins.Error
	}
	// A locking read sees a row committed after this transaction's first read,
	// which a plain read under MySQL's repeatable read would not.
	var existing Rule
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("environment_id = ? AND rule_type = ? AND identifier = ? AND scope = ? AND scope_value = ?",
			rule.EnvironmentID, rule.RuleType, rule.Identifier, rule.Scope, rule.ScopeValue).First(&existing).Error; err != nil {
		return rule, false, err
	}
	if strings.HasPrefix(existing.Policy, "ALLOWLIST") {
		return existing, false, nil
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
