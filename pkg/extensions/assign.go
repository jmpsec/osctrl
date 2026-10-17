package extensions

import (
	"fmt"
	"sort"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Expired reports whether the assignment has an expiry that is not after now.
func (n *NodeExtension) Expired(now time.Time) bool {
	return n.ExpiresAt != nil && !now.Before(*n.ExpiresAt)
}

// AssignEnv assigns an ordinary extension to an environment (idempotent).
func (m *Manager) AssignEnv(envID, extID uint, by string) error {
	e, err := m.Get(extID)
	if err != nil {
		return err
	}
	if e.CommandExecution {
		return ErrCommandExecution
	}
	return m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "environment_id"}, {Name: "extension_id"}},
		DoNothing: true,
	}).Create(&EnvExtension{EnvironmentID: envID, ExtensionID: extID, CreatedBy: by}).Error
}

// UnassignEnv removes an extension from an environment, or returns
// ErrNotFound when it was not assigned.
func (m *Manager) UnassignEnv(envID, extID uint) error {
	return deleted(m.db.Unscoped().Where("environment_id = ? AND extension_id = ?", envID, extID).Delete(&EnvExtension{}))
}

// deleted returns ErrNotFound when a delete matched no row.
func deleted(res *gorm.DB) error {
	if res.Error == nil && res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// EnvExtensions returns the extensions assigned to an environment, by name.
func (m *Manager) EnvExtensions(envID uint) ([]Extension, error) {
	var exts []Extension
	sub := m.db.Model(&EnvExtension{}).Select("extension_id").Where("environment_id = ?", envID)
	err := m.db.Where("id IN (?)", sub).Order("name").Find(&exts).Error
	return exts, err
}

// AssignNode assigns a command-execution extension to one node, creating or
// updating its environment and expiry.
func (m *Manager) AssignNode(nodeUUID string, envID, extID uint, expiresAt *time.Time, by string) (*NodeExtension, error) {
	if nodeUUID == "" || len(nodeUUID) > 255 {
		return nil, fmt.Errorf("%w: node uuid", ErrInvalid)
	}
	e, err := m.Get(extID)
	if err != nil {
		return nil, err
	}
	if !e.CommandExecution {
		return nil, ErrNotCommandExecution
	}
	row := &NodeExtension{NodeUUID: nodeUUID, EnvironmentID: envID, ExtensionID: extID, ExpiresAt: expiresAt, CreatedBy: by}
	err = m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}, {Name: "extension_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"environment_id", "expires_at", "created_by", "updated_at"}),
	}).Create(row).Error
	if err != nil {
		return nil, err
	}
	var stored NodeExtension
	if err := m.db.Where("node_uuid = ? AND extension_id = ?", nodeUUID, extID).First(&stored).Error; err != nil {
		return nil, err
	}
	return &stored, nil
}

// UnassignNode removes a node assignment and the node's status for that
// extension, so a later assignment never shows a stale status; a kept status
// is evidence the extension is still there and stays. It returns
// ErrNotFound when there was no assignment.
func (m *Manager) UnassignNode(nodeUUID string, extID uint) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var e Extension
		if err := tx.First(&e, extID).Error; err != nil {
			return notFound(err)
		}
		if err := deleted(tx.Unscoped().Where("node_uuid = ? AND extension_id = ?", nodeUUID, extID).Delete(&NodeExtension{})); err != nil {
			return err
		}
		// A kept status stays: osctrld could not remove the extension, and
		// only a later report (removed, ok) replaces it.
		return tx.Unscoped().Where("node_uuid = ? AND name = ? AND result <> ?", nodeUUID, e.Name, ResultKept).Delete(&NodeExtensionStatus{}).Error
	})
}

// NodeAssignments returns the node's assignments, expired ones included.
func (m *Manager) NodeAssignments(nodeUUID string) ([]NodeExtension, error) {
	var rows []NodeExtension
	err := m.db.Where("node_uuid = ?", nodeUUID).Order("extension_id").Find(&rows).Error
	return rows, err
}

// DeleteNode removes the node's assignments and statuses.
func (m *Manager) DeleteNode(nodeUUID string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(&NodeExtension{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(&NodeExtensionStatus{}).Error
	})
}

// withMode selects the ids of extensions whose CommandExecution is cmdExec.
// EffectiveSet and InEnvSet use it so environments only ever serve ordinary
// extensions and node assignments only command-execution ones, however the
// assignment rows got there (AssignEnv/AssignNode check without a lock).
func (m *Manager) withMode(cmdExec bool) *gorm.DB {
	return m.db.Model(&Extension{}).Select("id").Where("command_execution = ?", cmdExec)
}

// EffectiveSet returns what a node should run: the environment's extensions
// plus the node's unexpired assignments in that environment, each with its
// file for platform and arch (darwin falls back to universal). Extensions
// without a matching file are skipped. URL is left for the caller to fill.
func (m *Manager) EffectiveSet(envID uint, nodeUUID, platform, arch string, now time.Time) ([]types.OsctrldExtensionEntry, error) {
	var ids []uint
	if err := m.db.Model(&EnvExtension{}).Where("environment_id = ? AND extension_id IN (?)", envID, m.withMode(false)).Pluck("extension_id", &ids).Error; err != nil {
		return nil, err
	}
	var nodeRows []NodeExtension
	if err := m.db.Where("node_uuid = ? AND environment_id = ? AND extension_id IN (?)", nodeUUID, envID, m.withMode(true)).Find(&nodeRows).Error; err != nil {
		return nil, err
	}
	for _, n := range nodeRows {
		if !n.Expired(now) {
			ids = append(ids, n.ExtensionID)
		}
	}
	out := []types.OsctrldExtensionEntry{}
	if len(ids) == 0 {
		return out, nil
	}
	arches := []string{arch}
	if platform == "darwin" && arch != "universal" {
		arches = append(arches, "universal")
	}
	var files []ExtensionFile
	if err := m.db.Where("extension_id IN ? AND platform = ? AND arch IN ?", ids, platform, arches).Find(&files).Error; err != nil {
		return nil, err
	}
	pick := make(map[uint]ExtensionFile, len(files))
	for _, f := range files {
		if cur, ok := pick[f.ExtensionID]; !ok || cur.Arch != arch {
			pick[f.ExtensionID] = f
		}
	}
	var exts []Extension
	if err := m.db.Where("id IN ?", ids).Find(&exts).Error; err != nil {
		return nil, err
	}
	for _, e := range exts {
		if f, ok := pick[e.ID]; ok {
			out = append(out, types.OsctrldExtensionEntry{Name: e.Name, SHA256: f.SHA256, Size: f.Size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// InEnvSet reports whether sha is a file of an extension assigned to the
// environment or, unexpired, to any node in it. It gates downloads.
func (m *Manager) InEnvSet(envID uint, sha string) (bool, error) {
	var extIDs []uint
	if err := m.db.Model(&ExtensionFile{}).Where("sha256 = ?", sha).Distinct().Pluck("extension_id", &extIDs).Error; err != nil || len(extIDs) == 0 {
		return false, err
	}
	var n int64
	if err := m.db.Model(&EnvExtension{}).Where("environment_id = ? AND extension_id IN ? AND extension_id IN (?)", envID, extIDs, m.withMode(false)).Count(&n).Error; err != nil || n > 0 {
		return n > 0, err
	}
	var nodeRows []NodeExtension
	if err := m.db.Where("environment_id = ? AND extension_id IN ? AND extension_id IN (?)", envID, extIDs, m.withMode(true)).Find(&nodeRows).Error; err != nil {
		return false, err
	}
	now := time.Now()
	for _, r := range nodeRows {
		if !r.Expired(now) {
			return true, nil
		}
	}
	return false, nil
}
