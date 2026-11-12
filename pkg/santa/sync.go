package santa

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"gorm.io/gorm"
)

// RulePageSize is the number of rules returned per RuleDownload call.
const RulePageSize = 500

const maxEventField = 255

// ErrNoPreflight is returned when a sync stage arrives before any preflight.
var ErrNoPreflight = errors.New("santa: machine has not completed preflight")

// ErrRulesChanged is returned by RuleDownload when the effective rules differ
// from those digested at preflight; the client must abandon and re-sync.
var ErrRulesChanged = errors.New("santa: rules changed during sync")

// SyncNode identifies the authenticated node making a sync request.
type SyncNode struct {
	EnvID, NodeID uint
	UUID          string
	Tags          []string
}

func (n SyncNode) machineID() string { return strings.ToUpper(n.UUID) }

func (m *Manager) loadMachine(n SyncNode) (Machine, error) {
	mc, err := m.Machine(n.EnvID, n.machineID())
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mc, ErrNoPreflight
	}
	return mc, err
}

func (m *Manager) effectiveDigest(n SyncNode) ([]Rule, string, error) {
	rules, err := m.EffectiveRules(n.EnvID, n.UUID, n.Tags)
	if err != nil {
		return nil, "", err
	}
	return rules, RulesDigest(rules), nil
}

// Preflight records the machine and decides between a normal and a clean rule sync.
func (m *Manager) Preflight(n SyncNode, req *syncv1.PreflightRequest) (*syncv1.PreflightResponse, error) {
	cfg, err := m.Config(n.EnvID)
	if err != nil {
		return nil, err
	}
	mode, ok := syncv1.ClientMode_value[cfg.ClientMode]
	if !ok || mode == int32(syncv1.ClientMode_UNKNOWN_CLIENT_MODE) {
		return nil, fmt.Errorf("santa: invalid configured client mode %q", cfg.ClientMode)
	}
	_, digest, err := m.effectiveDigest(n)
	if err != nil {
		return nil, err
	}

	// Load-modify-save: SaveMachine overwrites every column.
	mc, err := m.Machine(n.EnvID, n.machineID())
	if errors.Is(err, gorm.ErrRecordNotFound) {
		mc = Machine{EnvironmentID: n.EnvID, MachineID: n.machineID()}
	} else if err != nil {
		return nil, err
	}
	now := m.now()
	mc.NodeID = n.NodeID
	mc.SerialNumber = req.GetSerialNumber()
	mc.Hostname = req.GetHostname()
	mc.OSVersion = req.GetOsVersion()
	mc.SantaVersion = req.GetSantaVersion()
	mc.PrimaryUser = req.GetPrimaryUser()
	mc.ClientMode = req.GetClientMode().String()
	// Compiler and transitive counts overlap other types, so they are left out.
	mc.RuleCount = req.GetBinaryRuleCount() + req.GetCertificateRuleCount() + req.GetTeamidRuleCount() +
		req.GetSigningidRuleCount() + req.GetCdhashRuleCount()
	syncType := syncv1.SyncType_NORMAL
	if req.GetRequestCleanSync() || digest != mc.AppliedDigest {
		syncType = syncv1.SyncType_CLEAN_RULES
	}
	mc.PendingSyncType = syncType.String()
	mc.PendingDigest = digest
	mc.LastPreflightAt = &now
	if err := m.SaveMachine(&mc); err != nil {
		return nil, err
	}

	resp := &syncv1.PreflightResponse{
		ClientMode:            syncv1.ClientMode(mode),
		SyncType:              syncType.Enum(),
		EnableTransitiveRules: &cfg.EnableTransitiveRules,
		BlockUsbMount:         &cfg.BlockUSBMount, //nolint:staticcheck // deprecated field is still the one older Santa clients read
	}
	if cfg.BatchSize > 0 {
		resp.BatchSize = cfg.BatchSize
	}
	return resp, nil
}

// RuleDownload returns one page of the node's effective rules for a clean sync.
func (m *Manager) RuleDownload(n SyncNode, req *syncv1.RuleDownloadRequest) (*syncv1.RuleDownloadResponse, error) {
	mc, err := m.loadMachine(n)
	if err != nil {
		return nil, err
	}
	resp := &syncv1.RuleDownloadResponse{}
	if mc.PendingSyncType != syncv1.SyncType_CLEAN_RULES.String() {
		return resp, nil
	}
	rules, digest, err := m.effectiveDigest(n)
	if err != nil {
		return nil, err
	}
	if digest != mc.PendingDigest {
		return nil, ErrRulesChanged
	}
	off := 0
	if c := req.GetCursor(); c != "" {
		off, err = strconv.Atoi(c)
		if err != nil || off < 0 || off > len(rules) {
			return nil, fmt.Errorf("santa: invalid rule cursor %q", c)
		}
	}
	end := min(off+RulePageSize, len(rules))
	for _, r := range rules[off:end] {
		pr, err := toProtoRule(r)
		if err != nil {
			return nil, err
		}
		resp.Rules = append(resp.Rules, pr)
	}
	if end < len(rules) {
		resp.Cursor = strconv.Itoa(end)
	}
	return resp, nil
}

func toProtoRule(r Rule) (*syncv1.Rule, error) {
	pol, ok := syncv1.Policy_value[r.Policy]
	if !ok || pol == int32(syncv1.Policy_POLICY_UNKNOWN) {
		return nil, fmt.Errorf("santa: rule %d has unmappable policy %q", r.ID, r.Policy)
	}
	rt, ok := syncv1.RuleType_value[r.RuleType]
	if !ok || rt == int32(syncv1.RuleType_RULETYPE_UNKNOWN) {
		return nil, fmt.Errorf("santa: rule %d has unmappable rule type %q", r.ID, r.RuleType)
	}
	return &syncv1.Rule{
		Identifier: r.Identifier,
		Policy:     syncv1.Policy(pol),
		RuleType:   syncv1.RuleType(rt),
		CustomMsg:  r.CustomMsg,
		CustomUrl:  r.CustomURL,
		CelExpr:    r.CELExpr,
	}, nil
}

// EventUpload stores execution events; other event kinds are ignored.
func (m *Manager) EventUpload(n SyncNode, req *syncv1.EventUploadRequest) (*syncv1.EventUploadResponse, error) {
	if _, err := m.loadMachine(n); err != nil {
		return nil, err
	}
	evs := make([]Event, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		if e == nil {
			continue
		}
		evs = append(evs, Event{
			EnvironmentID: n.EnvID,
			NodeID:        n.NodeID,
			MachineID:     n.machineID(),
			FileSHA256:    truncate(e.GetFileSha256(), maxEventField),
			FilePath:      truncate(e.GetFilePath(), maxEventField),
			FileName:      truncate(e.GetFileName(), maxEventField),
			ExecutingUser: truncate(e.GetExecutingUser(), maxEventField),
			Decision:      truncate(e.GetDecision().String(), maxEventField),
			TeamID:        truncate(e.GetTeamId(), maxEventField),
			SigningID:     truncate(e.GetSigningId(), maxEventField),
			CDHash:        truncate(e.GetCdhash(), maxEventField),
			BundleID:      truncate(e.GetFileBundleId(), maxEventField),
			ExecutedAt:    unixTime(e.GetExecutionTime()),
		})
	}
	if err := m.AddEvents(evs); err != nil {
		return nil, err
	}
	return &syncv1.EventUploadResponse{}, nil
}

// Postflight marks the preflight digest as applied.
func (m *Manager) Postflight(n SyncNode, _ *syncv1.PostflightRequest) (*syncv1.PostflightResponse, error) {
	mc, err := m.loadMachine(n)
	if err != nil {
		return nil, err
	}
	cfg, err := m.Config(n.EnvID)
	if err != nil {
		return nil, err
	}
	now := m.now()
	mc.AppliedDigest = mc.PendingDigest
	mc.LastSyncAt = &now
	mc.ClientMode = cfg.ClientMode
	if err := m.SaveMachine(&mc); err != nil {
		return nil, err
	}
	return &syncv1.PostflightResponse{}, nil
}

// unixTime converts float unix seconds to UTC; non-finite or absurd values yield the zero time.
func unixTime(f float64) time.Time {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

// truncate cuts s to at most max bytes without splitting a UTF-8 rune.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}
