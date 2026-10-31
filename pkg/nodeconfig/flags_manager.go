package nodeconfig

import (
	"context"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// FlagsOverride is a per-node osquery flags override: flagfile lines merged
// over the environment flags osctrld fetches.
type FlagsOverride struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex:idx_node_flags_overrides_node_uuid;size:255"`
	EnvironmentID uint   `gorm:"index:idx_node_flags_overrides_env"`
	Flags         string
	ExpiresAt     *time.Time
	UpdatedBy     string
}

// TableName keeps the table name stable.
func (FlagsOverride) TableName() string { return "node_flags_overrides" }

// Expired reports whether the override has an expiry that is not after now.
func (o *FlagsOverride) Expired(now time.Time) bool {
	return o.ExpiresAt != nil && !now.Before(*o.ExpiresAt)
}

func (o *FlagsOverride) activeIn(envID uint, now time.Time) bool {
	return o.EnvironmentID == envID && !o.Expired(now)
}

func flagsCacheKey(nodeUUID string) string { return "osctrl:nodeflags:" + nodeUUID }

// FlagsManager stores per-node flags overrides and osctrld status in SQL, with
// the same cache protocol as Manager in front of the overrides.
type FlagsManager struct {
	overrides[FlagsOverride, *FlagsOverride]
	// ReadDB is the optional read-replica connection; nil means none.
	ReadDB *gorm.DB
}

// Replica returns a manager that reads from the read replica, without the
// cache, or m itself when none is configured. Use it only for reads that
// tolerate replication lag (metrics), never on the osctrld request path.
func (m *FlagsManager) Replica() *FlagsManager {
	if m.ReadDB == nil {
		return m
	}
	r := &FlagsManager{}
	r.init(m.ReadDB, nil, flagsCacheKey, "node flags")
	return r
}

// NewFlagsManager migrates the tables. client may be nil, which disables the cache.
func NewFlagsManager(db *gorm.DB, client *redis.Client) (*FlagsManager, error) {
	return newFlagsManagerWithStore(db, storeFor(client))
}

func newFlagsManagerWithStore(db *gorm.DB, s store) (*FlagsManager, error) {
	if err := db.AutoMigrate(&FlagsOverride{}, &OsctrldStatus{}); err != nil {
		return nil, fmt.Errorf("migrating node flags overrides: %w", err)
	}
	m := &FlagsManager{}
	m.init(db, s, flagsCacheKey, "node flags")
	return m, nil
}

// Get returns the node's flags override straight from SQL, or nil if there is none.
func (m *FlagsManager) Get(nodeUUID string) (*FlagsOverride, error) {
	return m.loadSQL(nodeUUID)
}

// Set validates and upserts the flags override for o.NodeUUID, then caches it.
func (m *FlagsManager) Set(ctx context.Context, o FlagsOverride) (*FlagsOverride, error) {
	if err := ValidateFlagsOverride(o.Flags); err != nil {
		return nil, err
	}
	row := FlagsOverride{NodeUUID: o.NodeUUID, EnvironmentID: o.EnvironmentID, Flags: o.Flags, ExpiresAt: o.ExpiresAt, UpdatedBy: o.UpdatedBy}
	return m.save(ctx, o.NodeUUID, &row, "flags")
}

// Delete hard-deletes the node's flags override, then caches its absence.
func (m *FlagsManager) Delete(ctx context.Context, nodeUUID string) error {
	return m.remove(ctx, nodeUUID)
}

// Active returns the node's flags override if it exists, belongs to envID and
// has not expired. It does not validate the stored flags; callers re-validate.
func (m *FlagsManager) Active(ctx context.Context, nodeUUID string, envID uint, now time.Time) (*FlagsOverride, error) {
	return m.active(ctx, nodeUUID, envID, now)
}
