package nodeconfig

import (
	"errors"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// maxApplyError caps the osctrld-reported apply error stored per node.
const maxApplyError = 1024

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
