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
// queries — which is the common case (99%+ of check-ins). A short TTL
// (default 5s) ensures the cache doesn't serve stale queries for long;
// when a new query is created, affected nodes' cache entries are
// invalidated explicitly.
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
// entries. Short enough that a newly created query is visible within a
// few seconds, long enough to absorb repeated check-ins from the same
// node within the osquery distributed_interval (default 60s).
const DefaultQueryDispatchTTL = 5 * time.Second

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

// SetNoPendingQueries caches that this node currently has no pending
// queries. Called after a DB lookup returns empty.
func (c *QueryDispatchCache) SetNoPendingQueries(ctx context.Context, nodeID uint) {
	if c == nil || c.client == nil {
		return
	}
	if err := c.client.Set(ctx, cacheKey(nodeID), "1", c.ttl).Err(); err != nil {
		log.Debug().Err(err).Uint("node_id", nodeID).Msg("query dispatch cache: failed to set")
	}
}

// Invalidate removes the cache entry for a single node. Called when a
// new query is created that targets this node.
func (c *QueryDispatchCache) Invalidate(ctx context.Context, nodeID uint) {
	if c == nil || c.client == nil {
		return
	}
	c.client.Del(ctx, cacheKey(nodeID))
}

// InvalidateMany removes cache entries for multiple nodes. Called when a
// new query is created targeting many nodes. Uses pipelining to avoid
// N round-trips.
func (c *QueryDispatchCache) InvalidateMany(ctx context.Context, nodeIDs []uint) {
	if c == nil || c.client == nil || len(nodeIDs) == 0 {
		return
	}
	pipe := c.client.Pipeline()
	for _, id := range nodeIDs {
		pipe.Del(ctx, cacheKey(id))
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
