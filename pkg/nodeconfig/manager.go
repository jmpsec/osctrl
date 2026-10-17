package nodeconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// cachedState is what is kept in the cache: the override, or its absence.
type cachedState struct {
	Present  bool     `json:"present"`
	Override Override `json:"override"`
}

// Manager stores per-node overrides in SQL, with a Redis cache in front of the
// read path osctrl-tls takes on every osquery config request.
//
// SQL is the source of truth. Set and Delete write the full state into the
// cache after the SQL commit (never delete the key); Active only refills a
// cache miss with setNX, so it can never overwrite a newer write.
type Manager struct {
	db    *gorm.DB
	cache store
	load  func(nodeUUID string) (*Override, error)
}

// NewManager migrates the table. client may be nil, which disables the cache.
func NewManager(db *gorm.DB, client *redis.Client) (*Manager, error) {
	var s store
	if client != nil {
		s = redisStore{client: client}
	}
	return newManagerWithStore(db, s)
}

func newManagerWithStore(db *gorm.DB, s store) (*Manager, error) {
	if err := db.AutoMigrate(&Override{}); err != nil {
		return nil, fmt.Errorf("migrating node config overrides: %w", err)
	}
	m := &Manager{db: db, cache: s}
	m.load = m.loadSQL
	return m, nil
}

func (m *Manager) loadSQL(nodeUUID string) (*Override, error) {
	var o Override
	if err := m.db.Where("node_uuid = ?", nodeUUID).First(&o).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &o, nil
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
	err := m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}},
		DoUpdates: clause.AssignmentColumns([]string{"environment_id", "config", "expires_at", "updated_by", "updated_at"}),
	}).Create(&row).Error
	if err != nil {
		return nil, err
	}
	stored, err := m.loadSQL(o.NodeUUID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("override for node %s vanished after save", o.NodeUUID)
	}
	m.writeCache(ctx, o.NodeUUID, cachedState{Present: true, Override: *stored})
	return stored, nil
}

// Delete hard-deletes the node's override, then caches its absence.
func (m *Manager) Delete(ctx context.Context, nodeUUID string) error {
	if err := m.db.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(&Override{}).Error; err != nil {
		return err
	}
	m.writeCache(ctx, nodeUUID, cachedState{})
	return nil
}

// Active returns the node's override if it exists, belongs to envID and has not
// expired. It does not validate the stored config; callers re-validate.
func (m *Manager) Active(ctx context.Context, nodeUUID string, envID uint, now time.Time) (*Override, error) {
	state, err := m.state(ctx, nodeUUID)
	if err != nil {
		return nil, err
	}
	if !state.Present || state.Override.EnvironmentID != envID || state.Override.Expired(now) {
		return nil, nil
	}
	return &state.Override, nil
}

func (m *Manager) state(ctx context.Context, nodeUUID string) (cachedState, error) {
	key := cacheKey(nodeUUID)
	cacheable := m.cache != nil
	if cacheable {
		raw, ok, err := m.cache.get(ctx, key)
		switch {
		case err != nil:
			log.Debug().Err(err).Msg("node config cache read failed; falling back to SQL")
			cacheable = false
		case ok:
			var st cachedState
			if json.Unmarshal([]byte(raw), &st) == nil {
				return st, nil
			}
			log.Warn().Str("node", nodeUUID).Msg("node config cache entry is corrupt; falling back to SQL")
			cacheable = false
		}
	}
	o, err := m.load(nodeUUID)
	if err != nil {
		return cachedState{}, err
	}
	st := cachedState{}
	if o != nil {
		st = cachedState{Present: true, Override: *o}
	}
	if cacheable {
		if raw, err := json.Marshal(st); err == nil {
			if _, err := m.cache.setNX(ctx, key, string(raw), cacheTTL); err != nil {
				log.Debug().Err(err).Msg("node config cache refill failed")
			}
		}
	}
	return st, nil
}

// writeCache stores the full state; a failure is logged, not returned, since
// SQL is the source of truth and the worst case is one TTL of staleness.
func (m *Manager) writeCache(ctx context.Context, nodeUUID string, st cachedState) {
	if m.cache == nil {
		return
	}
	raw, err := json.Marshal(st)
	if err == nil {
		err = m.cache.set(ctx, cacheKey(nodeUUID), string(raw), cacheTTL)
	}
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg("node config cache write failed")
	}
}
