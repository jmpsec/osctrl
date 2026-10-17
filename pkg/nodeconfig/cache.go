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

const (
	cacheTTL      = time.Hour
	cacheOpBudget = 250 * time.Millisecond
)

func cacheKey(nodeUUID string) string { return "osctrl:nodeconfig:" + nodeUUID }

// store is the cache the managers use; a Redis implementation backs it.
type store interface {
	get(ctx context.Context, key string) (string, bool, error)
	set(ctx context.Context, key, value string, ttl time.Duration) error
	setNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

type redisStore struct{ client *redis.Client }

func (r redisStore) get(ctx context.Context, key string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, cacheOpBudget)
	defer cancel()
	v, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (r redisStore) set(ctx context.Context, key, value string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, cacheOpBudget)
	defer cancel()
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r redisStore) setNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, cacheOpBudget)
	defer cancel()
	return r.client.SetNX(ctx, key, value, ttl).Result()
}

// storeFor returns the Redis store, or nil (cache disabled) for a nil client.
func storeFor(client *redis.Client) store {
	if client == nil {
		return nil
	}
	return redisStore{client: client}
}

// overrideRow is a per-node override model (Override, FlagsOverride) keyed by
// a unique node_uuid column.
type overrideRow[T any] interface {
	*T
	activeIn(envID uint, now time.Time) bool
}

// cachedState is what is kept in the cache: the override, or its absence.
type cachedState[T any] struct {
	Present  bool `json:"present"`
	Override T    `json:"override"`
}

// overrides stores per-node override rows in SQL, with a Redis cache in front
// of the read path osctrl-tls takes on every osquery request. Manager and
// FlagsManager share it.
//
// SQL is the source of truth. save and remove write the full state into the
// cache after the SQL commit (never delete the key); active only refills a
// cache miss with setNX, so it can never overwrite a newer write.
type overrides[T any, P overrideRow[T]] struct {
	db    *gorm.DB
	cache store // nil disables the cache
	key   func(nodeUUID string) string
	label string // for logs, e.g. "node config"
	load  func(nodeUUID string) (*T, error)
}

func (s *overrides[T, P]) init(db *gorm.DB, cache store, key func(string) string, label string) {
	*s = overrides[T, P]{db: db, cache: cache, key: key, label: label}
	s.load = s.loadSQL
}

func (s *overrides[T, P]) loadSQL(nodeUUID string) (*T, error) {
	var o T
	if err := s.db.Where("node_uuid = ?", nodeUUID).First(&o).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &o, nil
}

// save upserts row by node_uuid, updating column and the common columns, then
// caches the stored row.
func (s *overrides[T, P]) save(ctx context.Context, nodeUUID string, row *T, column string) (*T, error) {
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}},
		DoUpdates: clause.AssignmentColumns([]string{"environment_id", column, "expires_at", "updated_by", "updated_at"}),
	}).Create(row).Error
	if err != nil {
		return nil, err
	}
	stored, err := s.loadSQL(nodeUUID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("override for node %s vanished after save", nodeUUID)
	}
	s.writeCache(ctx, nodeUUID, cachedState[T]{Present: true, Override: *stored})
	return stored, nil
}

// remove hard-deletes the node's row, then caches its absence.
func (s *overrides[T, P]) remove(ctx context.Context, nodeUUID string) error {
	if err := s.db.Unscoped().Where("node_uuid = ?", nodeUUID).Delete(new(T)).Error; err != nil {
		return err
	}
	s.writeCache(ctx, nodeUUID, cachedState[T]{})
	return nil
}

// active returns the node's row if it exists, belongs to envID and has not
// expired.
func (s *overrides[T, P]) active(ctx context.Context, nodeUUID string, envID uint, now time.Time) (*T, error) {
	st, err := s.state(ctx, nodeUUID)
	if err != nil {
		return nil, err
	}
	if !st.Present || !P(&st.Override).activeIn(envID, now) {
		return nil, nil
	}
	return &st.Override, nil
}

func (s *overrides[T, P]) state(ctx context.Context, nodeUUID string) (cachedState[T], error) {
	key := s.key(nodeUUID)
	cacheable := s.cache != nil
	if cacheable {
		raw, ok, err := s.cache.get(ctx, key)
		switch {
		case err != nil:
			log.Debug().Err(err).Msg(s.label + " cache read failed; falling back to SQL")
			cacheable = false
		case ok:
			var st cachedState[T]
			if json.Unmarshal([]byte(raw), &st) == nil {
				return st, nil
			}
			log.Warn().Str("node", nodeUUID).Msg(s.label + " cache entry is corrupt; falling back to SQL")
			cacheable = false
		}
	}
	o, err := s.load(nodeUUID)
	if err != nil {
		return cachedState[T]{}, err
	}
	st := cachedState[T]{}
	if o != nil {
		st = cachedState[T]{Present: true, Override: *o}
	}
	if cacheable {
		if raw, err := json.Marshal(st); err == nil {
			if _, err := s.cache.setNX(ctx, key, string(raw), cacheTTL); err != nil {
				log.Debug().Err(err).Msg(s.label + " cache refill failed")
			}
		}
	}
	return st, nil
}

// writeCache stores the full state; a failure is logged, not returned, since
// SQL is the source of truth and the worst case is one TTL of staleness.
func (s *overrides[T, P]) writeCache(ctx context.Context, nodeUUID string, st cachedState[T]) {
	if s.cache == nil {
		return
	}
	raw, err := json.Marshal(st)
	if err == nil {
		err = s.cache.set(ctx, s.key(nodeUUID), string(raw), cacheTTL)
	}
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg(s.label + " cache write failed")
	}
}
