package osqueryversions

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// RolloutStageWait is how long each stage stays open before the next one.
const RolloutStageWait = 2 * time.Hour

// RolloutStages are the stage shares in basis points (1%, 10%, 50%, 100%).
var RolloutStages = [4]uint32{100, 1000, 5000, 10000}

// Rollout states. "completed" is only ever an effective state of a running row.
const (
	RolloutRunning   = "running"
	RolloutPaused    = "paused"
	RolloutCompleted = "completed"
	RolloutAborted   = "aborted"
)

const maxRolloutRows = 10

// ErrRolloutState is returned when the rollout state does not allow a change.
var ErrRolloutState = errors.New("rollout is not in a state that allows this")

// Rollout is the staged rollout of an environment target. The effective stage
// is a pure function of the row and the clock, so no background job exists.
type Rollout struct {
	gorm.Model
	EnvironmentID uint   `gorm:"uniqueIndex:idx_osq_rollout_env_req"`
	RequestID     string `gorm:"uniqueIndex:idx_osq_rollout_env_req;size:32"`
	Version       string `gorm:"size:32"`
	State         string `gorm:"size:16"`
	Stage         int
	StageOpenedAt time.Time
	// Thresholds is the JSON of the [4]uint32 bucket thresholds.
	Thresholds   string `gorm:"size:96"`
	CreatedBy    string
	PausedHost   string
	PausedReason string
	PausedAt     *time.Time
	ResumedBy    string
	ResumedAt    *time.Time
	AbortedBy    string
	AbortedAt    *time.Time
}

// TableName keeps the table name stable.
func (Rollout) TableName() string { return "osquery_rollouts" }

// Bucket maps a node to a stable position in [0, 10000) for a rollout.
func Bucket(envID uint, version, nodeUUID string) uint32 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", envID, version, strings.ToUpper(nodeUUID))))
	return binary.BigEndian.Uint32(h[:4]) % 10000
}

// ComputeThresholds returns the stage thresholds for the given hosts: a host
// is eligible at stage i iff Bucket < thresholds[i]. Stage 1 has at least one host.
func ComputeThresholds(envID uint, version string, uuids []string) [4]uint32 {
	n := len(uuids)
	if n == 0 {
		return [4]uint32{RolloutStages[0], RolloutStages[1], RolloutStages[2], RolloutStages[3] + 1}
	}
	buckets := make([]uint32, n)
	for i, u := range uuids {
		buckets[i] = Bucket(envID, version, u)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i] < buckets[j] })
	var th [4]uint32
	for i := 0; i < 3; i++ {
		k := max(1, (n*int(RolloutStages[i])+9999)/10000)
		th[i] = buckets[k-1] + 1
	}
	th[3] = RolloutStages[3] + 1
	return th
}

// EffectiveStage is the 0-based stage open at now.
func (r Rollout) EffectiveStage(now time.Time) int {
	if r.State != RolloutRunning {
		return r.Stage
	}
	elapsed := now.Sub(r.StageOpenedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	return int(min(3, int64(r.Stage)+int64(elapsed/RolloutStageWait)))
}

// EffectiveState is the stored state, or completed once a running rollout reached the last stage.
func (r Rollout) EffectiveState(now time.Time) string {
	if r.State == RolloutRunning && r.EffectiveStage(now) == 3 {
		return RolloutCompleted
	}
	return r.State
}

// Eligible reports whether a host with this bucket may upgrade at now.
func (r Rollout) Eligible(bucket uint32, now time.Time) bool {
	var th [4]uint32
	if err := json.Unmarshal([]byte(r.Thresholds), &th); err != nil {
		return false
	}
	st := r.EffectiveStage(now)
	if st < 0 || st >= len(th) {
		return false
	}
	return bucket < th[st]
}

// NodeStage is the 0-based stage that first includes a host with this bucket,
// or -1 when the thresholds are invalid.
func (r Rollout) NodeStage(bucket uint32) int {
	var th [4]uint32
	if err := json.Unmarshal([]byte(r.Thresholds), &th); err != nil {
		return -1
	}
	for i, t := range th {
		if bucket < t {
			return i
		}
	}
	return -1
}

// NextStageAt is when the next stage opens, or nil unless running and not at the last stage.
func (r Rollout) NextStageAt(now time.Time) *time.Time {
	if r.EffectiveState(now) != RolloutRunning {
		return nil
	}
	t := r.StageOpenedAt.Add(time.Duration(r.EffectiveStage(now)-r.Stage+1) * RolloutStageWait)
	return &t
}

func isActive(state string) bool { return state == RolloutRunning || state == RolloutPaused }

// abortActive marks the environment's running or paused rollouts aborted.
func abortActive(tx *gorm.DB, envID uint, by string, now time.Time) error {
	return tx.Model(&Rollout{}).
		Where("environment_id = ? AND state IN ?", envID, []string{RolloutRunning, RolloutPaused}).
		Updates(map[string]any{"state": RolloutAborted, "aborted_by": by, "aborted_at": now}).Error
}

func latestRollout(tx *gorm.DB, envID uint) (*Rollout, error) {
	var r Rollout
	if err := tx.Where("environment_id = ?", envID).Order("id DESC").Limit(1).Find(&r).Error; err != nil || r.ID == 0 {
		return nil, err
	}
	return &r, nil
}

// SetEnvTargetRollout sets the environment target like SetEnvTarget and starts a
// rollout for it, aborting any active one, in one transaction.
func (m *Manager) SetEnvTargetRollout(envID uint, version, by string, uuids []string, now time.Time) (*EnvTarget, *Rollout, error) {
	if err := m.checkLibraryVersion(version); err != nil {
		return nil, nil, err
	}
	id, err := newRequestID()
	if err != nil {
		return nil, nil, err
	}
	th, err := json.Marshal(ComputeThresholds(envID, version, uuids))
	if err != nil {
		return nil, nil, err
	}
	var t EnvTarget
	r := Rollout{EnvironmentID: envID, RequestID: id, Version: version, State: RolloutRunning, StageOpenedAt: now, Thresholds: string(th), CreatedBy: by}
	err = m.db.Transaction(func(tx *gorm.DB) error {
		if err := upsertEnvTarget(tx, &t, envID, version, id, by); err != nil {
			return err
		}
		if err := abortActive(tx, envID, "replaced", now); err != nil {
			return err
		}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		// Prune the oldest finished rows beyond the newest maxRolloutRows.
		var rows []Rollout
		if err := tx.Where("environment_id = ?", envID).Order("id DESC").Find(&rows).Error; err != nil {
			return err
		}
		for i := maxRolloutRows; i < len(rows); i++ {
			if isActive(rows[i].State) {
				continue
			}
			if err := tx.Unscoped().Delete(&Rollout{}, rows[i].ID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &t, &r, nil
}

// GetRollout returns the environment's latest rollout, or nil when none exists.
func (m *Manager) GetRollout(envID uint) (*Rollout, error) {
	return latestRollout(m.db, envID)
}

// PauseRollout pauses the running rollout of request requestID, freezing its
// effective stage. eventAt is the server time the rollback was first recorded:
// a rollback that happened before the rollout was last resumed never pauses it
// (the host keeps re-reporting it). It returns false when no running rollout
// matches or the rollback is older than the last resume.
func (m *Manager) PauseRollout(envID uint, requestID, host, reason string, eventAt, now time.Time) (bool, error) {
	var r Rollout
	err := m.db.Where("environment_id = ? AND request_id = ?", envID, requestID).Limit(1).Find(&r).Error
	if err != nil || r.ID == 0 || r.State != RolloutRunning {
		return false, err
	}
	if r.ResumedAt != nil && !eventAt.After(*r.ResumedAt) {
		return false, nil
	}
	upd := map[string]any{"state": RolloutPaused, "stage": r.EffectiveStage(now)}
	if r.PausedHost == "" && r.PausedReason == "" && r.PausedAt == nil {
		upd["paused_host"], upd["paused_reason"], upd["paused_at"] = host, reason, now
	}
	res := m.db.Model(&Rollout{}).Where("id = ? AND state = ? AND stage_opened_at = ?", r.ID, RolloutRunning, r.StageOpenedAt).Updates(upd)
	return res.RowsAffected > 0, res.Error
}

// transition moves the latest rollout of envID from one of the from states to
// the updates, as a compare-and-set, and returns the updated row.
func (m *Manager) transition(envID uint, now time.Time, from []string, updates map[string]any, extra func(tx *gorm.DB) error) (*Rollout, error) {
	var out *Rollout
	err := m.db.Transaction(func(tx *gorm.DB) error {
		r, err := latestRollout(tx, envID)
		if err != nil {
			return err
		}
		if r == nil {
			return ErrNotFound
		}
		// The effective state decides: a stored running rollout past its last
		// stage is completed and cannot be aborted.
		if !slices.Contains(from, r.EffectiveState(now)) {
			return ErrRolloutState
		}
		res := tx.Model(&Rollout{}).Where("id = ? AND state IN ?", r.ID, from).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrRolloutState
		}
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		out, err = latestRollout(tx, envID)
		return err
	})
	return out, err
}

// ResumeRollout resumes a paused rollout at its frozen stage and restarts that stage's wait.
func (m *Manager) ResumeRollout(envID uint, by string, now time.Time) (*Rollout, error) {
	return m.transition(envID, now, []string{RolloutPaused},
		map[string]any{"state": RolloutRunning, "stage_opened_at": now, "resumed_by": by, "resumed_at": now,
			"paused_host": "", "paused_reason": "", "paused_at": nil}, nil)
}

// AbortRollout aborts a running or paused rollout and clears the environment
// target in the same transaction. Pins are kept.
func (m *Manager) AbortRollout(envID uint, by string, now time.Time) (*Rollout, error) {
	return m.transition(envID, now, []string{RolloutRunning, RolloutPaused},
		map[string]any{"state": RolloutAborted, "aborted_by": by, "aborted_at": now},
		func(tx *gorm.DB) error {
			return tx.Unscoped().Where("environment_id = ?", envID).Delete(&EnvTarget{}).Error
		})
}

// CountPaused returns environment id -> 1 for every environment whose latest
// rollout row (highest id) is stored as paused. One bounded query: at most
// maxRolloutRows rows are kept per environment.
func (m *Manager) CountPaused() (map[uint]int, error) {
	var ids []uint
	latest := m.db.Model(&Rollout{}).Select("MAX(id)").Group("environment_id")
	err := m.db.Model(&Rollout{}).Where("state = ? AND id IN (?)", RolloutPaused, latest).
		Pluck("environment_id", &ids).Error
	if err != nil {
		return nil, err
	}
	out := make(map[uint]int, len(ids))
	for _, id := range ids {
		out[id] = 1
	}
	return out, nil
}
