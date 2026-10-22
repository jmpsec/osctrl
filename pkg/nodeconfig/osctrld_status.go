package nodeconfig

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// maxApplyError caps the osctrld-reported apply error stored per node.
const maxApplyError = 1024

// ReportFreshness is how long an osctrld health report counts as current.
const ReportFreshness = 15 * time.Minute

var eventIDRe = regexp.MustCompile(`^[0-9]+:[0-9a-f]{64}$`)

var validStages = map[string]map[string]bool{
	"flags":      {"none": true, "environment": true, "last_known_good": true, "exhausted": true},
	"extensions": {"none": true, "restored": true, "exhausted": true},
}

// ValidStage reports whether stage is a known rollback stage for kind
// ("flags" or "extensions").
func ValidStage(kind, stage string) bool { return validStages[kind][stage] }

// ValidEventID reports whether id has the rollback event id format.
func ValidEventID(id string) bool { return eventIDRe.MatchString(id) }

// OsctrldStatus is the last flags fetch by a node's osctrld and the result of
// its last flags apply, as reported by osctrld.
type OsctrldStatus struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex:idx_osctrld_status_node_uuid;size:255"`
	EnvironmentID uint
	LastFetchedAt time.Time
	ApplyResult   string
	ApplySHA256   string
	ApplyError    string
	ApplyAt       *time.Time

	// Health report fields, written by RecordReport only.
	OsqueryRunning    *bool
	DownSince         *time.Time
	ReportedAt        *time.Time `gorm:"index"`
	FlagsStage        string     `gorm:"default:''"`
	ExtensionsStage   string     `gorm:"default:''"`
	FlagsEventID      string     `gorm:"default:''"`
	ExtensionsEventID string     `gorm:"default:''"`
}

// TableName keeps the table name stable.
func (OsctrldStatus) TableName() string { return "node_osctrld_status" }

// RecordFetch upserts the node's osctrld status. A nil apply keeps the
// previously reported apply fields.
func (m *FlagsManager) RecordFetch(nodeUUID string, envID uint, at time.Time, apply *types.OsctrldApplyStatus) error {
	row := OsctrldStatus{NodeUUID: nodeUUID, EnvironmentID: envID, LastFetchedAt: at}
	cols := []string{"environment_id", "last_fetched_at", "updated_at"}
	if apply != nil {
		row.ApplyResult = apply.Result
		row.ApplySHA256 = apply.SHA256
		// Cut at a rune boundary so the stored text stays valid UTF-8.
		row.ApplyError = apply.Error
		if len(row.ApplyError) > maxApplyError {
			row.ApplyError = strings.ToValidUTF8(row.ApplyError[:maxApplyError], "")
		}
		if !apply.At.IsZero() {
			applyAt := apply.At
			row.ApplyAt = &applyAt
		}
		cols = append(cols, "apply_result", "apply_sha256", "apply_error", "apply_at")
	}
	return m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}},
		DoUpdates: clause.AssignmentColumns(cols),
	}).Create(&row).Error
}

// Status returns the node's osctrld status, or nil if it never fetched flags.
func (m *FlagsManager) Status(nodeUUID string) (*OsctrldStatus, error) {
	var st OsctrldStatus
	if err := m.db.Where("node_uuid = ?", nodeUUID).First(&st).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &st, nil
}

// DeleteStatus hard-deletes the node's osctrld status.
func (m *FlagsManager) DeleteStatus(nodeUUID string) error {
	return m.db.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(&OsctrldStatus{}).Error
}

// RecordReport stores an osctrld health report. A kind (flags/extensions) with
// an invalid stage or event id is dropped, keeping its stored values. It
// returns the kinds whose non-none event id was not seen before; the
// compare-and-set on the event id column counts an event once across replicas.
func (m *FlagsManager) RecordReport(nodeUUID string, envID uint, r types.OsctrldStatusRequest, at time.Time) ([]string, error) {
	running := r.OsqueryRunning
	row := OsctrldStatus{NodeUUID: nodeUUID, EnvironmentID: envID, OsqueryRunning: &running, ReportedAt: &at}
	// Node clock: ignore implausible values, like the extensions status At.
	if d := r.DownSince; d != nil && d.Year() >= 1970 && d.Year() <= 9999 {
		row.DownSince = d
	}
	cols := []string{"environment_id", "osquery_running", "down_since", "reported_at", "updated_at"}

	kinds := []struct {
		name string
		in   types.OsctrldRollback
	}{{"flags", r.Flags}, {"extensions", r.Extensions}}
	var fresh []string // kinds that carry an event to dedupe
	for _, k := range kinds {
		if !ValidStage(k.name, k.in.Stage) {
			continue
		}
		// An empty event id is only valid with stage none.
		if (k.in.Stage != "none" || k.in.EventID != "") && !ValidEventID(k.in.EventID) {
			continue
		}
		if k.in.Stage != "none" {
			fresh = append(fresh, k.name)
		}
		if k.name == "flags" {
			row.FlagsStage = k.in.Stage
		} else {
			row.ExtensionsStage = k.in.Stage
		}
		cols = append(cols, k.name+"_stage")
	}
	if err := m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}},
		DoUpdates: clause.AssignmentColumns(cols),
	}).Create(&row).Error; err != nil {
		return nil, err
	}

	var newEvents []string
	for _, kind := range fresh {
		id := r.Flags.EventID
		if kind == "extensions" {
			id = r.Extensions.EventID
		}
		res := m.db.Model(&OsctrldStatus{}).
			Where("node_uuid = ? AND ("+kind+"_event_id IS NULL OR "+kind+"_event_id <> ?)", nodeUUID, id).
			Update(kind+"_event_id", id)
		if res.Error != nil {
			return newEvents, res.Error
		}
		if res.RowsAffected == 1 {
			newEvents = append(newEvents, kind)
		}
	}
	return newEvents, nil
}

// CountDown returns, per environment, the nodes whose fresh report says
// osqueryd is not running.
func (m *FlagsManager) CountDown(now time.Time) (map[uint]int, error) {
	var rows []struct {
		EnvironmentID uint
		N             int
	}
	if err := m.db.Model(&OsctrldStatus{}).
		Select("environment_id, COUNT(*) AS n").
		Where("osquery_running = ? AND reported_at >= ?", false, now.Add(-ReportFreshness)).
		Group("environment_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]int, len(rows))
	for _, r := range rows {
		out[r.EnvironmentID] = r.N
	}
	return out, nil
}
