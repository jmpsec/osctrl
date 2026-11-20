package santa

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
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
	// EnvUUID is the environment's external identifier, used in the approval request link.
	EnvUUID string
	UUID    string
	Tags    []string
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
	modeName, modeSource, err := m.EffectiveMode(n.EnvID, n.UUID, n.Tags)
	if err != nil {
		return nil, err
	}
	mode, ok := syncv1.ClientMode_value[modeName]
	if !ok || mode == int32(syncv1.ClientMode_UNKNOWN_CLIENT_MODE) {
		return nil, fmt.Errorf("santa: invalid configured client mode %q", modeName)
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
	mc.AssignedMode, mc.ModeSource = modeName, modeSource
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

	block := cfg.RemovableMedia == MediaBlock || cfg.RemovableMedia == MediaRemount
	resp := &syncv1.PreflightResponse{
		ClientMode:            syncv1.ClientMode(mode),
		SyncType:              syncType.Enum(),
		EnableTransitiveRules: &cfg.EnableTransitiveRules,
		RemovableMediaPolicy:  mediaPolicy(cfg.RemovableMedia, cfg.RemovableMediaFlags),
		// Clients that predate removable_media_policy read these instead; newer ones ignore them.
		BlockUsbMount: &block, //nolint:staticcheck // deprecated, kept for older clients
		// Always sent: Santa keeps its last value for an absent field, and an empty regex clears it.
		EnableBundles:             &cfg.EnableBundles,
		EnableAllEventUpload:      &cfg.EnableAllEventUpload,
		DisableUnknownEventUpload: &cfg.DisableUnknownEventUpload,
		AllowedPathRegex:          &cfg.AllowedPathRegex,
		BlockedPathRegex:          &cfg.BlockedPathRegex,
	}
	if cfg.RemovableMedia == MediaRemount {
		resp.RemountUsbMode = cfg.RemovableMediaFlags //nolint:staticcheck // deprecated, kept for older clients
	}
	if cfg.EncryptedRemovableMedia != "" {
		resp.EncryptedRemovableMediaPolicy = mediaPolicy(cfg.EncryptedRemovableMedia, cfg.EncryptedRemovableMediaFlags)
	}
	if cfg.BatchSize > 0 {
		resp.BatchSize = cfg.BatchSize
	}
	// 0 is omitted on the wire, so the client falls back to its own default.
	resp.FullSyncIntervalSeconds = cfg.FullSyncIntervalSeconds
	if a, ok := syncv1.FileAccessAction_value[cfg.OverrideFileAccessAction]; ok && a != 0 {
		resp.OverrideFileAccessAction = syncv1.FileAccessAction(a).Enum()
	}
	// Santa fills the placeholders when the user clicks the button in the block dialog.
	switch {
	case cfg.EventDetailURL != "":
		resp.SetEventDetailUrl(cfg.EventDetailURL)
		if cfg.EventDetailText != "" {
			resp.SetEventDetailText(cfg.EventDetailText)
		}
	case cfg.ApprovalURL != "" && n.EnvUUID != "":
		resp.SetEventDetailUrl(cfg.ApprovalURL + ApprovalRequestPath + url.PathEscape(n.EnvUUID) +
			"?sha256=%file_sha%&machine_id=%machine_id%")
		resp.SetEventDetailText(cmp.Or(cfg.EventDetailText, "Request approval"))
	}
	return resp, nil
}

// mediaPolicy maps a stored removable media action to the v1 message; anything
// unrecognized is sent as allow, matching the default config.
func mediaPolicy(action string, flags []string) *syncv1.RemovableMediaPolicy {
	switch action {
	case MediaBlock:
		return &syncv1.RemovableMediaPolicy{Action: &syncv1.RemovableMediaPolicy_Block{Block: true}}
	case MediaRemount:
		return &syncv1.RemovableMediaPolicy{Action: &syncv1.RemovableMediaPolicy_Remount{Remount: &syncv1.RemountPolicy{Flags: flags}}}
	default:
		return &syncv1.RemovableMediaPolicy{Action: &syncv1.RemovableMediaPolicy_Allow{Allow: true}}
	}
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

// EventUpload stores execution and file access events and asks for the
// binaries of new bundles; audit events are ignored.
func (m *Manager) EventUpload(n SyncNode, req *syncv1.EventUploadRequest) (*syncv1.EventUploadResponse, error) {
	evs, _, err := m.StoreEvents(n, req)
	if err != nil {
		return nil, err
	}
	bundles, err := m.BundlesWanted(n.EnvID, evs)
	if err != nil {
		return nil, err
	}
	return &syncv1.EventUploadResponse{EventUploadBundleBinaries: bundles}, nil
}

// DecisionBundleBinary is the decision of an event that only lists a binary of a bundle.
const DecisionBundleBinary = "BUNDLE_BINARY"

// BundlesWanted returns the bundle hashes in evs whose binaries the environment
// has not received yet, when bundles are enabled. The client then uploads each
// binary of those bundles as a BUNDLE_BINARY event.
func (m *Manager) BundlesWanted(envID uint, evs []Event) ([]string, error) {
	cfg, err := m.Config(envID)
	if err != nil || !cfg.EnableBundles {
		return nil, err
	}
	var hashes []string
	for _, e := range evs {
		if e.BundleHash != "" && e.Decision != DecisionBundleBinary && !slices.Contains(hashes, e.BundleHash) {
			hashes = append(hashes, e.BundleHash)
		}
	}
	if len(hashes) == 0 {
		return nil, nil
	}
	var have []string
	if err := m.DB.Model(&Event{}).Where("environment_id = ? AND decision = ? AND bundle_hash IN ?", envID, DecisionBundleBinary, hashes).
		Distinct().Pluck("bundle_hash", &have).Error; err != nil {
		return nil, err
	}
	return slices.DeleteFunc(hashes, func(h string) bool { return slices.Contains(have, h) }), nil
}

// StoreEvents stores the execution and file access events of an upload and
// returns them as stored, for forwarding to log sinks and alert rules.
func (m *Manager) StoreEvents(n SyncNode, req *syncv1.EventUploadRequest) ([]Event, []FileAccessEvent, error) {
	if _, err := m.loadMachine(n); err != nil {
		return nil, nil, err
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
			BundleName:    truncate(e.GetFileBundleName(), maxEventField),
			BundleVersion: truncate(cmp.Or(e.GetFileBundleVersionString(), e.GetFileBundleVersion()), maxEventField),
			BundlePath:    truncate(e.GetFileBundlePath(), maxEventField),
			BundleHash:    bundleHash(e.GetFileBundleHash()),
			SigningChain:  signingChain(e.GetSigningChain()),
		})
	}
	if err := m.AddEvents(evs); err != nil {
		return nil, nil, err
	}
	fa, err := m.addFileAccessEvents(n, req.GetFileAccessEvents())
	if err != nil {
		return nil, nil, err
	}
	return evs, fa, nil
}

// maxChainProcs caps the processes kept per file access event.
const maxChainProcs = 8

func (m *Manager) addFileAccessEvents(n SyncNode, in []*syncv1.FileAccessEvent) ([]FileAccessEvent, error) {
	now := m.now()
	evs := make([]FileAccessEvent, 0, len(in))
	for _, e := range in {
		if e == nil {
			continue
		}
		var chain []Process
		for _, p := range e.GetProcessChain() {
			if p == nil || len(chain) == maxChainProcs {
				continue
			}
			chain = append(chain, Process{
				Pid: p.GetPid(), FilePath: truncate(p.GetFilePath(), 1024), FileSHA256: truncate(p.GetFileSha256(), 64),
				SigningID: truncate(p.GetSigningId(), maxEventField), TeamID: truncate(p.GetTeamId(), maxEventField),
				CDHash: truncate(p.GetCdhash(), maxEventField),
			})
		}
		evs = append(evs, FileAccessEvent{
			CreatedAt: now, EnvironmentID: n.EnvID, NodeID: n.NodeID, MachineID: n.machineID(),
			RuleName:     truncate(e.GetRuleName(), maxEventField),
			RuleVersion:  truncate(e.GetRuleVersion(), maxEventField),
			Target:       truncate(e.GetTarget(), 1024),
			Decision:     strings.TrimPrefix(e.GetDecision().String(), "FILE_ACCESS_DECISION_"),
			AccessedAt:   unixTime(e.GetAccessTime()),
			ProcessChain: chain,
		})
	}
	if len(evs) == 0 {
		return nil, nil
	}
	return evs, m.DB.CreateInBatches(&evs, 200).Error
}

// FileAccessFilter narrows FileAccessEvents. Empty fields match everything.
type FileAccessFilter struct {
	// MachineID is the machine (node) UUID, matched without case.
	MachineID string
	// Target is a substring of the accessed path, matched without case.
	Target string
	// Process is a substring of the path of any process in the chain, matched without case.
	Process string
	// Decision is the exact decision: DENIED, DENIED_INVALID_SIGNATURE or AUDIT_ONLY.
	Decision string
}

// likeContains is a lowercase LIKE pattern for a substring; the query must
// use ESCAPE '!', which every supported database parses the same way.
func likeContains(s string) string {
	s = strings.NewReplacer(`!`, `!!`, `%`, `!%`, `_`, `!_`).Replace(strings.ToLower(s))
	return "%" + s + "%"
}

// FileAccessEvents lists an environment's file access events, newest first.
// It returns ErrInvalidEventFilter for a decision that is not a name, or a
// path filter longer than a stored path.
func (m *Manager) FileAccessEvents(envID uint, page, pageSize int, f FileAccessFilter) ([]FileAccessEvent, int64, error) {
	page = max(page, 1)
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	d := strings.ToUpper(f.Decision)
	if len(d) > 32 || strings.Trim(d, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != "" || len(f.Target) > 1024 || len(f.Process) > 1024 {
		return nil, 0, ErrInvalidEventFilter
	}
	q := m.DB.Model(&FileAccessEvent{}).Where("environment_id = ?", envID)
	if f.MachineID != "" {
		q = q.Where("machine_id = ?", strings.ToUpper(f.MachineID))
	}
	if d != "" {
		q = q.Where("decision = ?", d)
	}
	if f.Target != "" {
		q = q.Where(`LOWER(target) LIKE ? ESCAPE '!'`, likeContains(f.Target))
	}
	if f.Process != "" {
		// ponytail: LIKE on the chain's JSON text, so it also matches other process
		// fields, and a path with characters JSON escapes (", \, <, >, &) only
		// matches in escaped form. A process table if exact matching matters.
		q = q.Where(`LOWER(process_chain) LIKE ? ESCAPE '!'`, likeContains(f.Process))
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var evs []FileAccessEvent
	err := q.Order("created_at DESC, id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&evs).Error
	return evs, total, err
}

// AlertFields returns the fields alert rules can match, keyed by their JSON
// names; cert_* are the leaf certificate of the signing chain. Every value is
// written by the Santa client.
func (e Event) AlertFields() map[string]string {
	var leaf Cert
	if len(e.SigningChain) > 0 {
		leaf = e.SigningChain[0]
	}
	return map[string]string{
		"decision":       e.Decision,
		"file_sha256":    e.FileSHA256,
		"file_path":      e.FilePath,
		"file_name":      e.FileName,
		"executing_user": e.ExecutingUser,
		"team_id":        e.TeamID,
		"signing_id":     e.SigningID,
		"cd_hash":        e.CDHash,
		"bundle_id":      e.BundleID,
		"bundle_name":    e.BundleName,
		"bundle_version": e.BundleVersion,
		"bundle_path":    e.BundlePath,
		"bundle_hash":    e.BundleHash,
		"cert_sha256":    leaf.SHA256,
		"cert_cn":        leaf.CN,
		"cert_org":       leaf.Org,
		"cert_ou":        leaf.OU,
	}
}

// AlertFields returns the fields alert rules can match, keyed by their JSON
// names; process_* are the process that made the access. Every value is
// written by the Santa client.
func (e FileAccessEvent) AlertFields() map[string]string {
	var p Process
	if len(e.ProcessChain) > 0 {
		p = e.ProcessChain[0]
	}
	return map[string]string{
		"decision":           e.Decision,
		"target":             e.Target,
		"rule_name":          e.RuleName,
		"rule_version":       e.RuleVersion,
		"process_path":       p.FilePath,
		"process_sha256":     p.FileSHA256,
		"process_signing_id": p.SigningID,
		"process_team_id":    p.TeamID,
		"process_cd_hash":    p.CDHash,
	}
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

// maxChainCerts caps the certificates kept per event; real chains have three.
const maxChainCerts = 8

// signingChain copies a reported chain, leaf first, with bounded sizes.
func signingChain(certs []*syncv1.Certificate) []Cert {
	var out []Cert
	for _, c := range certs {
		if c == nil || len(out) == maxChainCerts {
			continue
		}
		out = append(out, Cert{
			SHA256: truncate(c.GetSha256(), 64), CN: truncate(c.GetCn(), maxEventField),
			Org: truncate(c.GetOrg(), maxEventField), OU: truncate(c.GetOu(), maxEventField),
			ValidFrom: time.Unix(int64(c.GetValidFrom()), 0).UTC(), ValidUntil: time.Unix(int64(c.GetValidUntil()), 0).UTC(),
		})
	}
	return out
}

// bundleHash keeps a reported bundle hash only when it is a SHA-256.
func bundleHash(h string) string {
	if !hex64.MatchString(h) {
		return ""
	}
	return strings.ToLower(h)
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
