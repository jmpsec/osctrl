package santa

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"
)

// LinkTTL is how long an approve or deny link works.
const LinkTTL = 72 * time.Hour

// ErrLinkInvalid is the one error for a link that is unknown, used, expired,
// from another environment or for the other action.
var ErrLinkInvalid = errors.New("santa: link is not valid any more")

// Request returns one request, gorm.ErrRecordNotFound if it is not in envID.
func (m *Manager) Request(envID, id uint) (Request, error) {
	var req Request
	if err := m.DB.Where("environment_id = ? AND id = ?", envID, id).First(&req).Error; err != nil {
		return req, err
	}
	reqs := []Request{req}
	err := m.attach(reqs)
	return reqs[0], err
}

// attachRisk fills the cached risk verdict of file requests; it leaves Risk
// nil when risk checks are off.
func (m *Manager) attachRisk(reqs []Request) error {
	var shas []string
	for _, r := range reqs {
		if r.Kind != RequestKindMonitor && r.FileSHA256 != "" {
			shas = append(shas, r.FileSHA256)
		}
	}
	risk, err := m.cachedRisk(shas)
	if err != nil || risk == nil {
		return err
	}
	for i := range reqs {
		if reqs[i].Kind != RequestKindMonitor {
			reqs[i].Risk = risk[strings.ToLower(reqs[i].FileSHA256)]
		}
	}
	return nil
}

// NewRequestLinks stores an approve and a deny link for req and returns their
// tokens, which are not stored and cannot be read back.
func (m *Manager) NewRequestLinks(req Request) (approve, deny string, err error) {
	tokens := make([]string, 2)
	links := make([]RequestLink, 2)
	for i := range links {
		if tokens[i], err = newToken(); err != nil {
			return "", "", err
		}
		links[i] = RequestLink{
			EnvironmentID: req.EnvironmentID, RequestID: req.ID, Approve: i == 0,
			TokenHash: hashToken(tokens[i]), ExpiresAt: m.now().Add(LinkTTL),
		}
	}
	return tokens[0], tokens[1], m.DB.Create(&links).Error
}

// DecideByLink decides the request a link token belongs to. The link must be
// unused, unexpired, in envID and for the action in d. It is consumed in the
// same transaction as the decision, so a decision that fails leaves it usable.
func (m *Manager) DecideByLink(envID uint, token string, d Decision) (Request, error) {
	// Risk checks call out over the network, so they run before the
	// transaction, on the request the link names; the link is checked again inside.
	if m.Risk != nil && d.Approve {
		var links []RequestLink
		if err := m.DB.Where("environment_id = ? AND token_hash = ?", envID, hashToken(token)).Limit(1).Find(&links).Error; err != nil {
			return Request{}, err
		}
		if len(links) == 0 {
			return Request{}, ErrLinkInvalid
		}
		if err := m.riskForDecision(m.DB, envID, links[0].RequestID, &d); err != nil {
			return Request{}, err
		}
	}
	var req Request
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var links []RequestLink
		if err := tx.Where("environment_id = ? AND token_hash = ?", envID, hashToken(token)).Limit(1).Find(&links).Error; err != nil {
			return err
		}
		now := m.now()
		if len(links) == 0 || links[0].UsedAt != nil || !now.Before(links[0].ExpiresAt) || links[0].Approve != d.Approve {
			return ErrLinkInvalid
		}
		// The used_at condition lets only one of two simultaneous uses through.
		res := tx.Model(&RequestLink{}).Where("id = ? AND used_at IS NULL", links[0].ID).
			Updates(map[string]any{"used_at": now, "used_by": d.By})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrLinkInvalid
		}
		var err error
		req, err = m.decideIn(tx, envID, links[0].RequestID, d)
		return err
	})
	return req, err
}

// PruneLinks deletes links that expired before now and returns how many.
func (m *Manager) PruneLinks(now time.Time) (int64, error) {
	res := m.DB.Where("expires_at < ?", now).Delete(&RequestLink{})
	return res.RowsAffected, res.Error
}

// DecisionLink is the URL of an approve or deny link. The token is the
// fragment, which browsers do not send to the server or put in the Referer.
func DecisionLink(base, envUUID string, requestID uint, approve bool, token string) string {
	action := "deny"
	if approve {
		action = "approve"
	}
	return fmt.Sprintf("%s%s%s?request=%d&action=%s#%s", base, ApprovalDecidePath, url.PathEscape(envUUID), requestID, action, token)
}

// oneLine collapses the whitespace of client- and user-written text, so it
// cannot fake extra lines in a notification.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// RequestNotice is the text of the notification for a new request: what was
// asked, by whom and why. The file name, requester and justification are
// written by the Santa client and the requester.
func RequestNotice(req Request) string {
	if req.Kind == RequestKindMonitor {
		return fmt.Sprintf("%s asks for MONITOR mode for %d hours on machine %s. Justification: %s",
			oneLine(req.Requester), req.MonitorHours, req.MachineID, oneLine(req.Justification))
	}
	name := oneLine(req.FileName)
	if name == "" {
		name = req.FileSHA256
	}
	return fmt.Sprintf("%s asks to allow %s (sha256 %s) on machine %s. Justification: %s",
		oneLine(req.Requester), name, req.FileSHA256, req.MachineID, oneLine(req.Justification))
}

// DecisionNotice is the title and text of the email that tells the requester
// how their request was decided, with the reason given.
func DecisionNotice(req Request) (title, text string) {
	what := "MONITOR mode on machine " + req.MachineID
	if req.Kind != RequestKindMonitor {
		name := oneLine(req.FileName)
		if name == "" {
			name = req.FileSHA256
		}
		what = fmt.Sprintf("allowing %s (sha256 %s) on machine %s", name, req.FileSHA256, req.MachineID)
	}
	verdict := "denied"
	if req.Status == RequestApproved {
		verdict = "approved"
	}
	text = fmt.Sprintf("Your request %d for %s was %s by %s.", req.ID, what, verdict, oneLine(req.DecidedBy))
	if req.Status == RequestApproved && req.Kind == RequestKindMonitor && req.DecidedAt != nil {
		until := req.DecidedAt.Add(time.Duration(req.MonitorHours) * time.Hour)
		text += " MONITOR mode starts at the machine's next sync and lasts until " + until.UTC().Format(time.RFC1123) + "."
	}
	if r := oneLine(req.Reason); r != "" {
		text += " Reason: " + r
	}
	return "Santa request " + verdict, text
}

// MonitorEndNotice is the title and text of the email that tells the requester
// their temporary MONITOR mode ended.
func MonitorEndNotice(o ModeOverride) (title, text string) {
	return "Santa MONITOR mode ended",
		"The temporary MONITOR mode on machine " + o.ScopeValue + " has ended; the machine goes back to its usual mode at its next sync."
}
