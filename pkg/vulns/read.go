package vulns

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Finding states for FindingFilter.State.
const (
	StateOpen     = "open"
	StateResolved = "resolved"
	StateAll      = "all"
)

const (
	defaultPageSize = 50
	maxPageSize     = 500
	topN            = 10
)

// ErrBadFilter is a filter value the API must reject with 400.
var ErrBadFilter = errors.New("invalid filter")

var validSeverities = map[string]bool{SeverityCritical: true, SeverityHigh: true, SeverityMedium: true, SeverityLow: true, SeverityUnknown: true}
var validConfidences = map[string]bool{ConfidenceConfirmed: true, ConfidencePossible: true}
var validStates = map[string]bool{"": true, StateOpen: true, StateResolved: true, StateAll: true}

// Reader answers the API's questions. Every query is scoped by environment
// (or node, which the handler has already checked against the environment).
type Reader struct {
	DB         *gorm.DB
	StaleAfter time.Duration
	now        func() time.Time
}

// NewReader returns a reader that reports feeds as stale after three missed
// sync intervals.
func NewReader(db *gorm.DB, syncInterval time.Duration) *Reader {
	if syncInterval <= 0 {
		syncInterval = DefaultSyncInterval
	}
	return &Reader{DB: db, StaleAfter: 3 * syncInterval, now: time.Now}
}

// FindingFilter selects findings. EnvironmentID is mandatory.
type FindingFilter struct {
	EnvironmentID uint
	NodeUUID      string
	Severity      string
	Confidence    string
	KEV           bool
	State         string
	Package       string
	Advisory      string
	Page          int
	PageSize      int
}

func (r *Reader) findingsQuery(f FindingFilter) (*gorm.DB, error) {
	if (f.Severity != "" && !validSeverities[f.Severity]) || (f.Confidence != "" && !validConfidences[f.Confidence]) || !validStates[f.State] {
		return nil, ErrBadFilter
	}
	q := r.DB.Model(&Finding{}).Where("environment_id = ?", f.EnvironmentID)
	if f.NodeUUID != "" {
		q = q.Where("node_uuid = ?", f.NodeUUID)
	}
	switch f.State {
	case StateResolved:
		q = q.Where("resolved_at IS NOT NULL")
	case StateAll:
	default:
		q = q.Where("resolved_at IS NULL")
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Confidence != "" {
		q = q.Where("confidence = ?", f.Confidence)
	}
	if f.KEV {
		q = q.Where("kev = ?", true)
	}
	if f.Package != "" {
		q = q.Where("package = ?", f.Package)
	}
	if f.Advisory != "" {
		q = q.Where("advisory_id = ?", f.Advisory)
	}
	return q, nil
}

// Findings returns one page of findings and the total matching the filter.
func (r *Reader) Findings(f FindingFilter) ([]Finding, int64, error) {
	page, size := f.Page, f.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = defaultPageSize
	}
	size = min(size, maxPageSize)
	q, err := r.findingsQuery(f)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	if err := q.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	out := []Finding{}
	err = q.Session(&gorm.Session{}).Order("kev DESC, id DESC").Offset((page - 1) * size).Limit(size).Find(&out).Error
	return out, total, err
}

// CountRow is one entry of a top-N list.
type CountRow struct {
	Name  string `json:"name"`
	Total int64  `json:"total"`
}

// Summary is the environment overview.
type Summary struct {
	Loaded     bool                        `json:"loaded"`
	Stale      bool                        `json:"stale"`
	BySeverity map[string]map[string]int64 `json:"by_severity"`
	KEV        int64                       `json:"kev"`
	// Possible counts open possible (NVD CPE) findings. KEV, AffectedNodes
	// and the top lists count confirmed findings only.
	Possible int64 `json:"possible"`
	// KEVPossible counts open possible findings that are known-exploited.
	KEVPossible   int64      `json:"kev_possible"`
	AffectedNodes int64      `json:"affected_nodes"`
	NotAssessed   int64      `json:"not_assessed"`
	TopAdvisories []CountRow `json:"top_advisories"`
	TopPackages   []CountRow `json:"top_packages"`
}

// Summary counts open findings in one environment.
func (r *Reader) Summary(envID uint) (Summary, error) {
	s := Summary{BySeverity: map[string]map[string]int64{}, TopAdvisories: []CountRow{}, TopPackages: []CountRow{}}
	open := func() *gorm.DB {
		return r.DB.Model(&Finding{}).Where("environment_id = ? AND resolved_at IS NULL", envID)
	}
	confirmed := func() *gorm.DB { return open().Where("confidence = ?", ConfidenceConfirmed) }
	var rows []struct {
		Severity   string
		Confidence string
		Total      int64
	}
	if err := open().Select("severity, confidence, COUNT(*) AS total").Group("severity, confidence").Scan(&rows).Error; err != nil {
		return s, err
	}
	for _, row := range rows {
		if s.BySeverity[row.Severity] == nil {
			s.BySeverity[row.Severity] = map[string]int64{}
		}
		s.BySeverity[row.Severity][row.Confidence] = row.Total
	}
	if err := confirmed().Where("kev = ?", true).Count(&s.KEV).Error; err != nil {
		return s, err
	}
	if err := open().Where("confidence = ?", ConfidencePossible).Count(&s.Possible).Error; err != nil {
		return s, err
	}
	if err := open().Where("confidence = ? AND kev = ?", ConfidencePossible, true).Count(&s.KEVPossible).Error; err != nil {
		return s, err
	}
	if err := confirmed().Distinct("node_uuid").Count(&s.AffectedNodes).Error; err != nil {
		return s, err
	}
	if err := r.DB.Model(&NodeState{}).Where("environment_id = ?", envID).
		Select("COALESCE(SUM(not_assessed), 0)").Scan(&s.NotAssessed).Error; err != nil {
		return s, err
	}
	if err := confirmed().Select("advisory_id AS name, COUNT(DISTINCT node_uuid) AS total").
		Group("advisory_id").Order("total DESC, name").Limit(topN).Scan(&s.TopAdvisories).Error; err != nil {
		return s, err
	}
	if err := confirmed().Select("package AS name, COUNT(DISTINCT node_uuid) AS total").
		Group("package").Order("total DESC, name").Limit(topN).Scan(&s.TopPackages).Error; err != nil {
		return s, err
	}
	var err error
	s.Loaded, s.Stale, err = r.freshness()
	return s, err
}

// AdvisoryDetail is one advisory and the nodes in one environment it affects.
type AdvisoryDetail struct {
	Advisory   Advisory  `json:"advisory"`
	Aliases    []string  `json:"aliases"`
	References []string  `json:"references"`
	Findings   []Finding `json:"findings"`
}

// Advisory returns gorm.ErrRecordNotFound for an unknown id.
func (r *Reader) Advisory(id string, envID uint) (AdvisoryDetail, error) {
	d := AdvisoryDetail{Aliases: []string{}, References: []string{}, Findings: []Finding{}}
	if err := r.DB.Where("id = ?", id).First(&d.Advisory).Error; err != nil {
		return d, err
	}
	_ = json.Unmarshal([]byte(d.Advisory.RefURLs), &d.References)
	if err := r.DB.Model(&Alias{}).Where("advisory_id = ? AND alias <> ?", id, id).Order("alias").Pluck("alias", &d.Aliases).Error; err != nil {
		return d, err
	}
	err := r.DB.Where("advisory_id = ? AND environment_id = ? AND resolved_at IS NULL", id, envID).
		Order("node_uuid").Limit(1000).Find(&d.Findings).Error
	return d, err
}

// NodeReport is one node's findings and assessment coverage.
type NodeReport struct {
	Findings    []Finding  `json:"findings"`
	NotAssessed int        `json:"not_assessed"`
	InventoryAt *time.Time `json:"inventory_at"`
	MatchedAt   *time.Time `json:"matched_at"`
	Loaded      bool       `json:"loaded"`
	Stale       bool       `json:"stale"`
}

// Node returns the open findings of one node in environment envID.
func (r *Reader) Node(uuid string, envID uint) (NodeReport, error) {
	rep := NodeReport{Findings: []Finding{}}
	if err := r.DB.Where("node_uuid = ? AND environment_id = ? AND resolved_at IS NULL", uuid, envID).
		Order("kev DESC, id DESC").Limit(maxPageSize).Find(&rep.Findings).Error; err != nil {
		return rep, err
	}
	var state NodeState
	if err := r.DB.Where("node_uuid = ?", uuid).Limit(1).Find(&state).Error; err != nil {
		return rep, err
	}
	if state.NodeUUID != "" {
		rep.NotAssessed, rep.MatchedAt = state.NotAssessed, state.MatchedAt
		inv := state.InventoryAt
		rep.InventoryAt = &inv
	}
	var err error
	rep.Loaded, rep.Stale, err = r.freshness()
	return rep, err
}

// FeedStatus is the admin view of the feeds and the worker.
type FeedStatus struct {
	Sources         []SyncState `json:"sources"`
	LastSyncAt      *time.Time  `json:"last_sync_at"`
	SyncRequestedAt *time.Time  `json:"sync_requested_at"`
	LastSyncFailed  bool        `json:"last_sync_failed"`
	Loaded          bool        `json:"loaded"`
	Stale           bool        `json:"stale"`
}

// Feeds reports each feed's progress.
func (r *Reader) Feeds() (FeedStatus, error) {
	fs := FeedStatus{Sources: []SyncState{}}
	if err := r.DB.Order("source").Find(&fs.Sources).Error; err != nil {
		return fs, err
	}
	var ws WorkerState
	if err := r.DB.Where("name = ?", workerName).Limit(1).Find(&ws).Error; err != nil {
		return fs, err
	}
	fs.LastSyncAt, fs.SyncRequestedAt, fs.LastSyncFailed = ws.LastSyncAt, ws.SyncRequestedAt, ws.LastSyncFailed
	var err error
	fs.Loaded, fs.Stale, err = r.freshness()
	return fs, err
}

// freshness: loaded once any OSV ecosystem has synced; stale when any known
// feed has not succeeded within StaleAfter. Zero findings before loading
// must never be presented as "no vulnerabilities".
func (r *Reader) freshness() (loaded, stale bool, err error) {
	var states []SyncState
	if err := r.DB.Find(&states).Error; err != nil {
		return false, false, err
	}
	now := r.now()
	for _, st := range states {
		if strings.HasPrefix(st.Source, osvSourcePrefix) && st.LastSuccess != nil {
			loaded = true
		}
		if st.LastSuccess == nil || now.Sub(*st.LastSuccess) > r.StaleAfter {
			stale = true
		}
	}
	return loaded, loaded && stale, nil
}
