package santa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Risk verdicts, per check and aggregated.
const (
	RiskClean   = "clean"
	RiskFlagged = "flagged"
	// RiskUnknown means the check has no data on the file (not an error).
	RiskUnknown = "unknown"
	// RiskError means the check could not answer; votes fail closed on it.
	RiskError = "error"
	// RiskUnchecked is only reported from the cache: no check has run yet.
	RiskUnchecked = "unchecked"
)

// riskErrorTTL is how long a failed check is cached, so an outage is shown
// and not retried on every request.
const riskErrorTTL = 5 * time.Minute

// maxRiskBody caps a check's response.
const maxRiskBody = 1 << 20

var (
	// ErrRiskFlagged is returned when a risk check flagged the file.
	ErrRiskFlagged = errors.New("santa: a risk check flagged this file")
	// ErrRiskUnavailable is returned when a risk check could not answer and the
	// action fails closed.
	ErrRiskUnavailable = errors.New("santa: a risk check could not answer; try again later")
)

// RiskCheck looks up the reputation of a file hash. Only the hash is sent.
type RiskCheck interface {
	Name() string
	Check(ctx context.Context, sha256 string) (verdict, detail string, err error)
}

// Verdict is the cached answer of one check for one hash.
type Verdict struct {
	ID        uint      `gorm:"primarykey" json:"-"`
	SHA256    string    `gorm:"type:varchar(64);uniqueIndex:idx_santa_verdict" json:"-"`
	CheckName string    `gorm:"type:varchar(32);uniqueIndex:idx_santa_verdict" json:"check"`
	Verdict   string    `gorm:"type:varchar(16)" json:"verdict"`
	Detail    string    `gorm:"type:varchar(255)" json:"detail"`
	CheckedAt time.Time `json:"checked_at"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
}

// TableName for Verdict
func (Verdict) TableName() string { return "santa_verdicts" }

// Risk is the aggregated verdict of every configured check for a hash.
type Risk struct {
	// flagged if any check flagged, error if any failed, clean if any found it
	// clean, unknown when none knows it, unchecked when nothing is cached
	Verdict string    `json:"verdict"`
	Checks  []Verdict `json:"checks"`
}

// RiskEngine runs the risk checks and caches their verdicts. Checks are the
// service-wide ones; an environment can run none or its own instead
// (EnvConfig.RiskChecks).
type RiskEngine struct {
	Checks  []RiskCheck
	TTL     time.Duration
	Timeout time.Duration
	// Client calls VirusTotal for environment checks; PublicClient calls
	// environment webhooks, whose URL an admin sets through the API.
	Client       *http.Client
	PublicClient *http.Client
}

// envCheck is an environment's own check: its name carries the environment,
// so its verdicts are cached apart from the service-wide check's.
type envCheck struct {
	RiskCheck
	name string
}

// Name of the check.
func (c envCheck) Name() string { return c.name }

// envCheckNames are the cache names of the environment's own checks.
func envCheckNames(envID uint) []string {
	return []string{fmt.Sprintf("virustotal@%d", envID), fmt.Sprintf("webhook@%d", envID)}
}

// checksFor returns the risk checks of the environment; none means risk
// checks are off there.
func (m *Manager) checksFor(envID uint) ([]RiskCheck, error) {
	if m.Risk == nil {
		return nil, nil
	}
	cfg, err := m.Config(envID)
	if err != nil {
		return nil, err
	}
	switch cfg.RiskChecks {
	case RiskChecksNone:
		return nil, nil
	case RiskChecksEnv:
		names := envCheckNames(envID)
		var out []RiskCheck
		if cfg.RiskVirusTotalKey != "" {
			out = append(out, envCheck{VirusTotal{Key: cfg.RiskVirusTotalKey, Threshold: int(cfg.RiskVirusTotalThreshold), Client: m.Risk.Client}, names[0]})
		}
		if cfg.RiskWebhookURL != "" {
			out = append(out, envCheck{RiskWebhook{URL: cfg.RiskWebhookURL, Secret: cfg.RiskWebhookSecret, Client: m.Risk.PublicClient}, names[1]})
		}
		return out, nil
	}
	return m.Risk.Checks, nil
}

// ClearEnvRiskCache drops the cached verdicts of the environment's own checks,
// after their settings change.
func (m *Manager) ClearEnvRiskCache(envID uint) error {
	return m.DB.Where("check_name IN ?", envCheckNames(envID)).Delete(&Verdict{}).Error
}

// RiskEnabled reports whether the environment runs any risk check.
func (m *Manager) RiskEnabled(envID uint) (bool, error) {
	checks, err := m.checksFor(envID)
	return len(checks) > 0, err
}

// NewPublicClient returns an HTTP client that connects directly, never
// through a proxy, and refuses loopback, link-local and private addresses at
// connect time, after DNS resolution, so a rebinding hostname cannot reach
// an internal service.
func NewPublicClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("refusing to connect to non-public address %s", host)
		}
		return nil
	}}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func aggregate(checks []Verdict) string {
	has := map[string]bool{}
	for _, c := range checks {
		has[c.Verdict] = true
	}
	switch {
	case len(checks) == 0:
		return RiskUnchecked
	case has[RiskFlagged]:
		return RiskFlagged
	case has[RiskError]:
		return RiskError
	case has[RiskClean]:
		return RiskClean
	}
	return RiskUnknown
}

// cachedRisk reads the fresh cached verdicts of the hashes in the environment,
// without running any check. Every hash gets an entry; it is nil when risk
// checks are off there.
func (m *Manager) cachedRisk(envID uint, shas []string) (map[string]*Risk, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	checks, err := m.checksFor(envID)
	if err != nil || len(checks) == 0 {
		return nil, err
	}
	lower := make([]string, 0, len(shas))
	for _, s := range shas {
		lower = append(lower, strings.ToLower(s))
	}
	var rows []Verdict
	if err := m.DB.Where("sha256 IN ? AND expires_at > ?", lower, m.now()).Order("check_name").Find(&rows).Error; err != nil {
		return nil, err
	}
	configured := map[string]bool{}
	for _, c := range checks {
		configured[c.Name()] = true
	}
	byHash := map[string][]Verdict{}
	for _, r := range rows {
		if configured[r.CheckName] {
			byHash[r.SHA256] = append(byHash[r.SHA256], r)
		}
	}
	out := make(map[string]*Risk, len(lower))
	for _, s := range lower {
		out[s] = &Risk{Verdict: aggregate(byHash[s]), Checks: byHash[s]}
	}
	return out, nil
}

// CheckRisk returns the verdict of every check of the environment for the
// hash, running the checks whose cached verdict is missing or expired, in
// parallel. It returns nil when risk checks are off there.
func (m *Manager) CheckRisk(ctx context.Context, envID uint, sha256 string) (*Risk, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if !hex64.MatchString(sha256) {
		return nil, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	}
	checks, err := m.checksFor(envID)
	if err != nil || len(checks) == 0 {
		return nil, err
	}
	cached, err := m.cachedRisk(envID, []string{sha256})
	if err != nil {
		return nil, err
	}
	have := map[string]Verdict{}
	for _, v := range cached[sha256].Checks {
		have[v.CheckName] = v
	}
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		fresh []Verdict
	)
	for _, c := range checks {
		if v, ok := have[c.Name()]; ok {
			fresh = append(fresh, v)
			continue
		}
		wg.Add(1)
		go func(c RiskCheck) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, m.Risk.Timeout)
			defer cancel()
			verdict, detail, err := c.Check(cctx, sha256)
			now := m.now()
			v := Verdict{SHA256: sha256, CheckName: c.Name(), Verdict: verdict, Detail: oneLine(detail), CheckedAt: now, ExpiresAt: now.Add(m.Risk.TTL)}
			if err != nil || (verdict != RiskClean && verdict != RiskFlagged && verdict != RiskUnknown) {
				if err == nil {
					err = fmt.Errorf("invalid verdict %q", truncate(verdict, 32))
				}
				v.Verdict, v.Detail, v.ExpiresAt = RiskError, oneLine(err.Error()), now.Add(riskErrorTTL)
			}
			v.Detail = truncate(v.Detail, maxEventField)
			mu.Lock()
			fresh = append(fresh, v)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	for _, v := range fresh {
		if v.ID != 0 {
			continue
		}
		v := v
		if err := m.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "sha256"}, {Name: "check_name"}},
			DoUpdates: clause.AssignmentColumns([]string{"verdict", "detail", "checked_at", "expires_at"}),
		}).Create(&v).Error; err != nil {
			return nil, err
		}
	}
	return &Risk{Verdict: aggregate(fresh), Checks: fresh}, nil
}

// PruneVerdicts deletes verdicts that expired before now.
func (m *Manager) PruneVerdicts(now time.Time) (int64, error) {
	res := m.DB.Where("expires_at < ?", now).Delete(&Verdict{})
	return res.RowsAffected, res.Error
}

// stripURL keeps a request URL, which may carry a key or token, out of errors.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// VirusTotal checks a hash against VirusTotal's file report.
type VirusTotal struct {
	Key string
	// Engines that must flag the file for a flagged verdict.
	Threshold int
	// BaseURL defaults to https://www.virustotal.com; tests point it elsewhere.
	BaseURL string
	Client  *http.Client
}

// Name of the check.
func (VirusTotal) Name() string { return "virustotal" }

// Check returns flagged when at least Threshold engines call the file
// malicious, unknown when VirusTotal has never seen it.
func (v VirusTotal) Check(ctx context.Context, sha256 string) (string, string, error) {
	base := v.BaseURL
	if base == "" {
		base = "https://www.virustotal.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v3/files/"+sha256, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("x-apikey", v.Key)
	resp, err := v.Client.Do(req)
	if err != nil {
		return "", "", stripURL(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return RiskUnknown, "not in VirusTotal", nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", "", errors.New("VirusTotal rejected the API key")
	case http.StatusTooManyRequests:
		return "", "", errors.New("VirusTotal quota exceeded")
	default:
		return "", "", fmt.Errorf("VirusTotal answered %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Attributes struct {
				Stats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRiskBody)).Decode(&body); err != nil {
		return "", "", fmt.Errorf("VirusTotal response: %w", err)
	}
	stats := body.Data.Attributes.Stats
	total := 0
	for _, n := range stats {
		total += n
	}
	detail := fmt.Sprintf("%d of %d engines flag it", stats["malicious"], total)
	if stats["malicious"] >= max(v.Threshold, 1) {
		return RiskFlagged, detail, nil
	}
	return RiskClean, detail, nil
}

// RiskWebhook asks a custom HTTP service for a verdict.
type RiskWebhook struct {
	URL    string
	Secret string
	Client *http.Client
}

// Name of the check.
func (RiskWebhook) Name() string { return "webhook" }

// Check POSTs {"sha256": ...}, signed with X-Osctrl-Signature when a secret
// is set, and expects {"verdict": "clean|flagged|unknown", "detail": ...}.
func (w RiskWebhook) Check(ctx context.Context, sha256 string) (string, string, error) {
	body, err := json.Marshal(map[string]string{"sha256": sha256})
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return "", "", stripURL(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "osctrl-santa")
	if w.Secret != "" {
		mac := hmac.New(sha256Hash, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-Osctrl-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return "", "", stripURL(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("risk webhook answered %d", resp.StatusCode)
	}
	var out struct {
		Verdict string `json:"verdict"`
		Detail  string `json:"detail"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRiskBody)).Decode(&out); err != nil {
		return "", "", fmt.Errorf("risk webhook response: %w", err)
	}
	return out.Verdict, out.Detail, nil
}

var sha256Hash = sha256.New

// riskForDecision runs the checks before a binary approval, outside any
// transaction. It leaves d alone for denials, MONITOR requests and when risk
// checks are off.
func (m *Manager) riskForDecision(db *gorm.DB, envID, id uint, d *Decision) error {
	if !d.Approve {
		return nil
	}
	var req Request
	if err := db.Where("environment_id = ? AND id = ?", envID, id).First(&req).Error; err != nil {
		return err
	}
	if req.Kind == RequestKindMonitor || req.Status != RequestPending {
		return nil
	}
	risk, err := m.CheckRisk(context.Background(), envID, req.FileSHA256)
	if err != nil || risk == nil {
		return err
	}
	d.risk = risk.Verdict
	return nil
}

// RiskOverride lets votes go ahead in an environment for a file that a risk
// check flagged or could not check. It does not change the verdict, and
// approvals keep their own override.
type RiskOverride struct {
	ID            uint      `gorm:"primarykey" json:"-"`
	CreatedAt     time.Time `json:"created_at"`
	EnvironmentID uint      `gorm:"uniqueIndex:idx_santa_risk_override" json:"-"`
	SHA256        string    `gorm:"type:varchar(64);uniqueIndex:idx_santa_risk_override" json:"-"`
	CreatedBy     string    `gorm:"type:varchar(255)" json:"created_by"`
	Reason        string    `gorm:"type:varchar(1024)" json:"reason"`
}

// TableName for RiskOverride
func (RiskOverride) TableName() string { return "santa_risk_overrides" }

// SetRiskOverride stores (or replaces) the voting override of a file.
func (m *Manager) SetRiskOverride(envID uint, sha256, by, reason string) (RiskOverride, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	reason = strings.TrimSpace(reason)
	switch {
	case !hex64.MatchString(sha256):
		return RiskOverride{}, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	case reason == "" || utf8.RuneCountInString(reason) > MaxJustification:
		return RiskOverride{}, fmt.Errorf("%w: a reason of at most %d characters is required", ErrInvalidRequest, MaxJustification)
	case by == "":
		return RiskOverride{}, fmt.Errorf("%w: created by is required", ErrInvalidRequest)
	}
	o := RiskOverride{CreatedAt: m.now(), EnvironmentID: envID, SHA256: sha256, CreatedBy: by, Reason: reason}
	if err := m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "environment_id"}, {Name: "sha256"}},
		DoUpdates: clause.AssignmentColumns([]string{"created_at", "created_by", "reason"}),
	}).Create(&o).Error; err != nil {
		return RiskOverride{}, err
	}
	return o, nil
}

// DeleteRiskOverride removes the voting override of a file and reports whether there was one.
func (m *Manager) DeleteRiskOverride(envID uint, sha256 string) (bool, error) {
	res := m.DB.Where("environment_id = ? AND sha256 = ?", envID, strings.ToLower(strings.TrimSpace(sha256))).Delete(&RiskOverride{})
	return res.RowsAffected > 0, res.Error
}

// riskOverride returns the voting override of a file, or nil.
func (m *Manager) riskOverride(envID uint, sha256 string) (*RiskOverride, error) {
	var os []RiskOverride
	if err := m.DB.Where("environment_id = ? AND sha256 = ?", envID, strings.ToLower(sha256)).Limit(1).Find(&os).Error; err != nil || len(os) == 0 {
		return nil, err
	}
	return &os[0], nil
}
