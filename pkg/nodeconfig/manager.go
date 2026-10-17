package nodeconfig

import (
	"context"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// Manager stores per-node configuration overrides in SQL, with a Redis cache
// in front of the read path osctrl-tls takes on every osquery config request.
//
// SQL is the source of truth. Set and Delete write the full state into the
// cache after the SQL commit (never delete the key); Active only refills a
// cache miss with setNX, so it can never overwrite a newer write.
type Manager struct {
	overrides[Override, *Override]
}

// NewManager migrates the table. client may be nil, which disables the cache.
func NewManager(db *gorm.DB, client *redis.Client) (*Manager, error) {
	return newManagerWithStore(db, storeFor(client))
}

func newManagerWithStore(db *gorm.DB, s store) (*Manager, error) {
	if err := db.AutoMigrate(&Override{}); err != nil {
		return nil, fmt.Errorf("migrating node config overrides: %w", err)
	}
	m := &Manager{}
	m.init(db, s, cacheKey, "node config")
	return m, nil
}

func (o *Override) activeIn(envID uint, now time.Time) bool {
	return o.EnvironmentID == envID && !o.Expired(now)
}

// Get returns the node's override straight from SQL, or nil if there is none.
func (m *Manager) Get(nodeUUID string) (*Override, error) {
	return m.loadSQL(nodeUUID)
}

// Set validates and upserts the override for o.NodeUUID, then caches it.
func (m *Manager) Set(ctx context.Context, o Override) (*Override, error) {
	if err := Validate(o.Config); err != nil {
		return nil, err
	}
	row := Override{NodeUUID: o.NodeUUID, EnvironmentID: o.EnvironmentID, Config: o.Config, ExpiresAt: o.ExpiresAt, UpdatedBy: o.UpdatedBy}
	return m.save(ctx, o.NodeUUID, &row, "config")
}

// Delete hard-deletes the node's override, then caches its absence.
func (m *Manager) Delete(ctx context.Context, nodeUUID string) error {
	return m.remove(ctx, nodeUUID)
}

// Active returns the node's override if it exists, belongs to envID and has not
// expired. It does not validate the stored config; callers re-validate.
func (m *Manager) Active(ctx context.Context, nodeUUID string, envID uint, now time.Time) (*Override, error) {
	return m.active(ctx, nodeUUID, envID, now)
}
