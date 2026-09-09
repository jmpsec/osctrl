package queries

import (
	"context"
	"errors"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// QueryDispatchCache caches the result of NodeQueries per node in Redis.
// The primary goal is to skip the DB JOIN when a node has no pending
// queries. When a new query is created, affected nodes' cache entries
// are invalidated explicitly; WATCH prevents an in-flight empty lookup
// from overwriting that invalidation.
//
// The cache stores a boolean: true means "no pending queries for this
// node" (the DB returned empty). A cache miss or false falls through to
// the DB. We only cache the empty result because non-empty results are
// rare and the query SQL itself can be large.
type QueryDispatchCache struct {
	client *redis.Client
	ttl    time.Duration
}

const queryDispatchCachePrefix = "osctrl:tls:query-dispatch"

// DefaultQueryDispatchTTL is the TTL for "no queries pending" cache
// entries. It spans the default 60s poll interval and bounds staleness
// if explicit invalidation fails.
const DefaultQueryDispatchTTL = 2 * time.Minute

// NewQueryDispatchCache creates a Redis-backed cache for query dispatch.
// Pass nil to disable caching (tests, standalone mode).
func NewQueryDispatchCache(client *redis.Client, ttl time.Duration) *QueryDispatchCache {
	if ttl <= 0 {
		ttl = DefaultQueryDispatchTTL
	}
	return &QueryDispatchCache{client: client, ttl: ttl}
}

// HasNoPendingQueries returns true if the cache knows this node has no
// pending queries. ok=false means the cache doesn't know — fall through
// to the DB.
func (c *QueryDispatchCache) HasNoPendingQueries(ctx context.Context, nodeID uint) (ok bool, err error) {
	if c == nil || c.client == nil {
		return false, nil
	}
	val, err := c.client.Get(ctx, cacheKey(nodeID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	return string(val) == "1", nil
}

// read caches only successful empty lookups. Redis failures fall back to SQL;
// an invalidated lookup still returns its SQL result but cannot refill the cache.
func (c *QueryDispatchCache) read(ctx context.Context, nodeID uint, lookup func() (QueryReadQueries, bool, error)) (QueryReadQueries, bool, error) {
	if c == nil || c.client == nil {
		return lookup()
	}
	cached, err := c.HasNoPendingQueries(ctx, nodeID)
	if err != nil {
		log.Debug().Err(err).Uint("node_id", nodeID).Msg("query dispatch cache: read error")
		return lookup()
	}
	if cached {
		return QueryReadQueries{}, false, nil
	}

	var result QueryReadQueries
	var accelerate, loaded bool
	var lookupErr error
	key := cacheKey(nodeID)
	err = c.client.Watch(ctx, func(tx *redis.Tx) error {
		value, err := tx.Get(ctx, key).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}
		if value == "1" {
			result, loaded = QueryReadQueries{}, true
			return nil
		}
		result, accelerate, lookupErr = lookup()
		loaded = true
		if lookupErr != nil || len(result) != 0 {
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, "1", c.ttl)
			return nil
		})
		return err
	}, key)
	if err != nil && !errors.Is(err, redis.TxFailedErr) {
		log.Debug().Err(err).Uint("node_id", nodeID).Msg("query dispatch cache: fill error")
	}
	if !loaded {
		return lookup()
	}
	return result, accelerate, lookupErr
}

// Invalidate clears the empty hint for a single node. Called when a
// new query is created that targets this node.
func (c *QueryDispatchCache) Invalidate(ctx context.Context, nodeID uint) {
	if c == nil || c.client == nil {
		return
	}
	// DEL on an absent key does not invalidate WATCH. SET also fences readers
	// that started their SQL lookup with a cache miss.
	if err := c.client.Set(ctx, cacheKey(nodeID), "0", c.ttl).Err(); err != nil {
		log.Debug().Err(err).Uint("node_id", nodeID).Msg("query dispatch cache: invalidate failed")
	}
}

// InvalidateMany clears empty hints for multiple nodes. Called when a
// new query is created targeting many nodes. Uses pipelining to avoid
// N round-trips.
func (c *QueryDispatchCache) InvalidateMany(ctx context.Context, nodeIDs []uint) {
	if c == nil || c.client == nil || len(nodeIDs) == 0 {
		return
	}
	pipe := c.client.Pipeline()
	for _, id := range nodeIDs {
		pipe.Set(ctx, cacheKey(id), "0", c.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		log.Debug().Err(err).Int("count", len(nodeIDs)).Msg("query dispatch cache: invalidate many failed")
	}
}

func cacheKey(nodeID uint) string {
	// uint to string without fmt for performance
	return queryDispatchCachePrefix + ":" + uintToStr(nodeID)
}

// uintToStr converts a uint to its decimal string representation
// without importing fmt — this is on the hot path (every check-in).
func uintToStr(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
