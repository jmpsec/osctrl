// Package osqueryversions stores the osquery versions osctrl can roll out and
// the SHA-256 of each official package.
package osqueryversions

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrInvalid is returned for invalid versions or entries.
var ErrInvalid = errors.New("invalid osquery version input")

// ErrNotFound is returned when a version has no library entries.
var ErrNotFound = errors.New("osquery version not found")

// ErrInUse is returned when a change would break a target or pin referencing a version.
var ErrInUse = errors.New("osquery version is in use by a target or pin")

// Manager is the source of truth for the osquery version library, shared by
// osctrl-api and osctrl-tls through SQL.
type Manager struct {
	db *gorm.DB
	// ReadDB is the optional read-replica connection; nil means none.
	ReadDB *gorm.DB
}

// Replica returns a manager that reads from the read replica, or m itself when
// none is configured. Use it only for reads that tolerate replication lag
// (metrics), never for targets, pins or rollout decisions.
func (m *Manager) Replica() *Manager {
	if m.ReadDB == nil {
		return m
	}
	return &Manager{db: m.ReadDB}
}

// NewManager migrates the library tables and returns a manager.
func NewManager(db *gorm.DB) (*Manager, error) {
	if err := db.AutoMigrate(&DigestEntry{}, &EnvTarget{}, &NodePin{}, &Rollout{}); err != nil {
		return nil, fmt.Errorf("migrating osquery versions: %w", err)
	}
	return &Manager{db: db}, nil
}

// PutEntries validates all entries and then upserts them, per
// (version, platform, arch, format), in one transaction.
func (m *Manager) PutEntries(version string, entries []DigestEntry, by string) error {
	if !ValidVersion(version) {
		return fmt.Errorf("%w: version %q", ErrInvalid, version)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%w: no entries", ErrInvalid)
	}
	// Five combinations are supported, so refusing repeats also caps entries at five.
	seen := make(map[[3]string]bool, len(entries))
	for _, e := range entries {
		if err := ValidEntry(e.Platform, e.Arch, e.Format, e.SHA256); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		k := [3]string{e.Platform, e.Arch, e.Format}
		if seen[k] {
			return fmt.Errorf("%w: duplicate entry %s/%s/%s", ErrInvalid, e.Platform, e.Arch, e.Format)
		}
		seen[k] = true
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		inUse, err := versionInUse(tx, version, time.Now())
		if err != nil {
			return err
		}
		if inUse {
			for _, e := range entries {
				var cur DigestEntry
				err := tx.Where("version = ? AND platform = ? AND arch = ? AND format = ?", version, e.Platform, e.Arch, e.Format).Limit(1).Find(&cur).Error
				if err != nil {
					return err
				}
				if cur.ID != 0 && cur.SHA256 != e.SHA256 {
					return fmt.Errorf("%w: %s", ErrInUse, version)
				}
			}
		}
		for _, e := range entries {
			row := DigestEntry{Version: version, Platform: e.Platform, Arch: e.Arch, Format: e.Format, SHA256: e.SHA256, CreatedBy: by}
			err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "version"}, {Name: "platform"}, {Name: "arch"}, {Name: "format"}},
				DoUpdates: clause.AssignmentColumns([]string{"sha256", "created_by"}),
			}).Create(&row).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetEntries returns the digests of a version.
func (m *Manager) GetEntries(version string) ([]DigestEntry, error) {
	var out []DigestEntry
	err := m.db.Where("version = ?", version).Order("platform, arch, format").Find(&out).Error
	return out, err
}

// ListVersions returns every version, newest first, with its digests.
func (m *Manager) ListVersions() ([]VersionView, error) {
	var rows []DigestEntry
	if err := m.db.Order("platform, arch, format").Find(&rows).Error; err != nil {
		return nil, err
	}
	idx := map[string]int{}
	views := []VersionView{}
	for _, r := range rows {
		i, ok := idx[r.Version]
		if !ok {
			i = len(views)
			idx[r.Version] = i
			views = append(views, VersionView{Version: r.Version})
		}
		views[i].Entries = append(views[i].Entries, r)
	}
	now := time.Now()
	for i := range views {
		inUse, err := versionInUse(m.db, views[i].Version, now)
		if err != nil {
			return nil, err
		}
		views[i].InUse = inUse
	}
	sort.SliceStable(views, func(i, j int) bool {
		c, err := Compare(views[i].Version, views[j].Version)
		return err == nil && c > 0
	})
	return views, nil
}

// VersionNames returns the versions that have library entries, oldest first,
// without digests or in-use queries.
func (m *Manager) VersionNames() ([]string, error) {
	names := []string{}
	if err := m.db.Model(&DigestEntry{}).Distinct().Pluck("version", &names).Error; err != nil {
		return nil, err
	}
	sort.SliceStable(names, func(i, j int) bool {
		c, err := Compare(names[i], names[j])
		return err == nil && c < 0
	})
	return names, nil
}

// DeleteVersion removes every digest of a version. It returns ErrInUse when a
// target or an unexpired pin references it and ErrNotFound when it has no rows.
func (m *Manager) DeleteVersion(version string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		inUse, err := versionInUse(tx, version, time.Now())
		if err != nil {
			return err
		}
		if inUse {
			return fmt.Errorf("%w: %s", ErrInUse, version)
		}
		res := tx.Where("version = ?", version).Delete(&DigestEntry{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// versionInUse reports whether any environment target or unexpired pin uses version.
func versionInUse(tx *gorm.DB, version string, now time.Time) (bool, error) {
	var n int64
	if err := tx.Model(&EnvTarget{}).Where("version = ?", version).Count(&n).Error; err != nil || n > 0 {
		return n > 0, err
	}
	// Expiry is checked in Go: SQLite compares stored times as text, which
	// breaks across zone offsets.
	var pins []NodePin
	if err := tx.Where("version = ?", version).Find(&pins).Error; err != nil {
		return false, err
	}
	for _, p := range pins {
		if !p.Expired(now) {
			return true, nil
		}
	}
	return false, nil
}

func newRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// checkLibraryVersion validates version and requires it to exist in the library.
func (m *Manager) checkLibraryVersion(version string) error {
	if !ValidVersion(version) {
		return fmt.Errorf("%w: version %q", ErrInvalid, version)
	}
	var n int64
	if err := m.db.Model(&DigestEntry{}).Where("version = ?", version).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, version)
	}
	return nil
}

// SetEnvTarget sets the environment's target to a library version with a new
// request id. It does NOT start or replace a rollout: API code must use
// SetEnvTargetRollout.
func (m *Manager) SetEnvTarget(envID uint, version, by string) (*EnvTarget, error) {
	if err := m.checkLibraryVersion(version); err != nil {
		return nil, err
	}
	id, err := newRequestID()
	if err != nil {
		return nil, err
	}
	var t EnvTarget
	err = m.db.Transaction(func(tx *gorm.DB) error {
		return upsertEnvTarget(tx, &t, envID, version, id, by)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// upsertEnvTarget writes the environment's target row into t.
func upsertEnvTarget(tx *gorm.DB, t *EnvTarget, envID uint, version, id, by string) error {
	e := tx.Unscoped().Where("environment_id = ?", envID).Limit(1).Find(t).Error
	if e == nil && t.ID == 0 {
		*t = EnvTarget{EnvironmentID: envID, Version: version, RequestID: id, UpdatedBy: by}
		return tx.Create(t).Error
	}
	if e != nil {
		return e
	}
	t.Version, t.RequestID, t.UpdatedBy = version, id, by
	return tx.Unscoped().Save(t).Error
}

// GetEnvTarget returns the environment's target, or nil when none is set.
func (m *Manager) GetEnvTarget(envID uint) (*EnvTarget, error) {
	var t EnvTarget
	if err := m.db.Where("environment_id = ?", envID).Limit(1).Find(&t).Error; err != nil || t.ID == 0 {
		return nil, err
	}
	return &t, nil
}

// ClearEnvTarget removes the environment's target and reports whether one was set.
func (m *Manager) ClearEnvTarget(envID uint) (bool, error) {
	var cleared bool
	err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := abortActive(tx, envID, "target cleared", time.Now()); err != nil {
			return err
		}
		res := tx.Unscoped().Where("environment_id = ?", envID).Delete(&EnvTarget{})
		cleared = res.RowsAffected > 0
		return res.Error
	})
	return cleared, err
}

// SetPin pins a node to a library version. expiresAt, when set, must be in the
// future. Changing only the expiry of a pin of the same environment keeps its request id, so osctrld
// does not retry a version the host rejected; any other call, including an
// identical re-save (how an operator retries), gets a new request id.
func (m *Manager) SetPin(nodeUUID string, envID uint, version string, expiresAt *time.Time, by string) (*NodePin, error) {
	if nodeUUID == "" {
		return nil, fmt.Errorf("%w: empty node uuid", ErrInvalid)
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("%w: expiry must be in the future", ErrInvalid)
	}
	if err := m.checkLibraryVersion(version); err != nil {
		return nil, err
	}
	id, err := newRequestID()
	if err != nil {
		return nil, err
	}
	var p NodePin
	err = m.db.Transaction(func(tx *gorm.DB) error {
		e := tx.Unscoped().Where("node_uuid = ?", nodeUUID).Limit(1).Find(&p).Error
		if e == nil && p.ID == 0 {
			p = NodePin{NodeUUID: nodeUUID, EnvironmentID: envID, Version: version, RequestID: id, UpdatedBy: by, ExpiresAt: expiresAt}
			return tx.Create(&p).Error
		}
		if e != nil {
			return e
		}
		// A pin row of another environment is a first pin here: new id.
		if p.EnvironmentID != envID || p.Version != version || sameExpiry(p.ExpiresAt, expiresAt) {
			p.RequestID = id
		}
		p.EnvironmentID, p.Version, p.UpdatedBy, p.ExpiresAt = envID, version, by, expiresAt
		return tx.Unscoped().Save(&p).Error
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// sameExpiry treats expiries less than a second apart as the same: databases
// keep (and round) sub-second precision differently.
func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Sub(*b).Abs() < time.Second
}

// GetPin returns the node's pin (expired or not), or nil when none is set.
func (m *Manager) GetPin(nodeUUID string) (*NodePin, error) {
	var p NodePin
	if err := m.db.Where("node_uuid = ?", nodeUUID).Limit(1).Find(&p).Error; err != nil || p.ID == 0 {
		return nil, err
	}
	return &p, nil
}

// DeletePin removes the node's pin and reports whether one was set.
func (m *Manager) DeletePin(nodeUUID string) (bool, error) {
	res := m.db.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(&NodePin{})
	return res.RowsAffected > 0, res.Error
}

// DeleteNodeRecords removes everything stored for a node; used by node deletion.
func (m *Manager) DeleteNodeRecords(nodeUUID string) error {
	_, err := m.DeletePin(nodeUUID)
	return err
}
