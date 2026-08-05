package environments

import (
	"context"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
)

const (
	cacheName                = "environments"
	redisEnvCacheName        = "osctrl:tls:environment"
	RedisEnvInvalidatePrefix = "envcache:invalidate:"
	// envCacheTTL is the maximum time a TLSEnvironment can sit in the
	// EnvCache before the next request refetches from the database.
	//
	// osctrl-tls and osctrl-api share this Redis-backed cache across
	// processes. The TTL bounds the window during which enroll-secret
	// rotations, env deletions, or config-PATCH changes can be served
	// stale if Redis invalidation is unavailable.
	//
	// 5 minutes: the fallback window if no invalidation signal is
	// received. With Redis-backed EnvCache invalidation wired in, config
	// PATCHes are picked up immediately; this TTL only bounds the worst
	// case. 5m keeps DB load low while limiting staleness.
	envCacheTTL = 5 * time.Minute
	// envCacheDegradedTTL is the TTL used when the DB health monitor
	// reports the database as degraded. Extending the TTL during a DB
	// outage keeps cached envs available longer so the service can
	// keep serving osquery nodes that already have a cached env row.
	// Capped at 60m so a long outage does not serve enroll secrets
	// indefinitely — rotated secrets would still be accepted for up
	// to this window, which is the documented trade-off.
	envCacheDegradedTTL = 60 * time.Minute
)

// EnvCache provides cached access to TLS environments
type EnvCache struct {
	// The cache itself, storing Environment objects
	cache       *cache.MemoryCache[TLSEnvironment]
	redisCache  *cache.RedisJSONCache[TLSEnvironment]
	redisClient *redis.Client

	// Reference to the environment manager for cache misses
	envs EnvManager

	// invalidationCheck is called on each GetByUUID. If it returns
	// true, the cached entry is stale and the env is refetched from
	// the DB. Set via SetInvalidationCheck for compatibility with
	// external invalidation signals.
	invalidationCheck func(ctx context.Context, uuid string) bool

	// dbHealth, when non-nil, gates stale-serve and TTL extension
	// during DB outages. nil means "no monitor" and the cache behaves
	// as before: TTL expiry + DB miss returns an error.
	dbHealth backend.DegradedReader
}

// NewEnvCache creates a new environment cache
func NewEnvCache(envs EnvManager) *EnvCache {
	envCache := cache.NewMemoryCache(
		cache.WithCleanupInterval[TLSEnvironment](envCacheTTL),
		cache.WithName[TLSEnvironment](cacheName),
	)

	return &EnvCache{
		cache: envCache,
		envs:  envs,
	}
}

// NewRedisEnvCache creates a Redis-backed environment cache.
func NewRedisEnvCache(envs EnvManager, client *redis.Client) *EnvCache {
	return &EnvCache{
		redisCache:  cache.NewRedisJSONCache[TLSEnvironment](client, redisEnvCacheName),
		redisClient: client,
		envs:        envs,
	}
}

// SetInvalidationCheck wires a callback that is called on each
// GetByUUID. If the callback returns true, the cached entry is
// considered stale and the env is refetched from the DB.
func (ec *EnvCache) SetInvalidationCheck(fn func(ctx context.Context, uuid string) bool) {
	ec.invalidationCheck = fn
}

// SetDBHealth wires a DB health monitor. When the monitor reports
// the database as degraded, GetByUUID serves stale cached entries
// instead of returning an error on a DB miss, and writes during
// degradation use envCacheDegradedTTL so the cache stays warm longer.
// Pass nil to disable stale-serve (the default).
func (ec *EnvCache) SetDBHealth(h backend.DegradedReader) {
	ec.dbHealth = h
}

// GetByUUID retrieves an environment by UUID, using cache when available.
//
// During a DB outage (when a DB health monitor is wired via SetDBHealth
// and reports IsDegraded), GetByUUID serves a stale cached entry on a
// DB miss instead of returning an error. This keeps osquery nodes
// that already have a cached env row serving requests (config, log,
// query) for the duration of the outage, bounded by envCacheStaleMaxAge
// so rotated enroll secrets are not accepted indefinitely.
func (ec *EnvCache) GetByUUID(ctx context.Context, uuid string) (TLSEnvironment, error) {
	// Check if a cross-process invalidation signal has been received
	// (e.g., osctrl-api patched the config and set a Redis key).
	if ec.invalidationCheck != nil && ec.invalidationCheck(ctx, uuid) {
		ec.InvalidateEnv(ctx, uuid)
		if ec.redisClient != nil {
			_ = ec.redisClient.Del(ctx, RedisEnvInvalidatePrefix+uuid).Err()
		}
	}

	if ec.redisCache != nil {
		if env, found, err := ec.redisCache.Get(ctx, uuid); err == nil && found {
			return env, nil
		} else if err != nil {
			_ = ec.redisCache.Delete(ctx, uuid)
		}

		env, err := ec.envs.GetByUUID(uuid)
		if err != nil {
			if ec.dbHealth != nil && ec.dbHealth.IsDegraded() {
				if stale, found, _ := ec.redisCache.GetStale(ctx, uuid); found {
					return stale, nil
				}
			}
			return TLSEnvironment{}, err
		}
		ttl := envCacheTTL
		if ec.dbHealth != nil && ec.dbHealth.IsDegraded() {
			ttl = envCacheDegradedTTL
		}
		_ = ec.redisCache.Set(ctx, uuid, env, ttl)
		return env, nil
	}

	// Try to get from cache first
	if env, found := ec.cache.Get(ctx, uuid); found {
		return env, nil
	}

	// Not in cache, fetch from database
	env, err := ec.envs.GetByUUID(uuid)
	if err != nil {
		if ec.dbHealth != nil && ec.dbHealth.IsDegraded() {
			if stale, found := ec.cache.GetStale(ctx, uuid); found {
				return stale, nil
			}
		}
		return TLSEnvironment{}, err
	}

	ttl := envCacheTTL
	if ec.dbHealth != nil && ec.dbHealth.IsDegraded() {
		ttl = envCacheDegradedTTL
	}
	ec.cache.Set(ctx, uuid, env, ttl)

	return env, nil
}

// InvalidateEnv removes a specific environment from the cache. Callers
// that mutate env rows in the same process SHOULD invoke this so the
// next request refetches the row without waiting for the TTL.
func (ec *EnvCache) InvalidateEnv(ctx context.Context, uuid string) {
	if ec.redisCache != nil {
		_ = ec.redisCache.Delete(ctx, uuid)
		return
	}
	ec.cache.Delete(ctx, uuid)
}

// InvalidateAll clears the entire cache. Used on bulk operations or
// after operator-driven secret rotations.
func (ec *EnvCache) InvalidateAll(ctx context.Context) {
	if ec.redisCache != nil {
		return
	}
	ec.cache.Clear(ctx)
}

// UpdateEnvInCache updates an environment in the cache
func (ec *EnvCache) UpdateEnvInCache(ctx context.Context, env TLSEnvironment) {
	if ec.redisCache != nil {
		_ = ec.redisCache.Set(ctx, env.UUID, env, envCacheTTL)
		return
	}
	ec.cache.Set(ctx, env.UUID, env, envCacheTTL)
}

// Close stops the cleanup goroutine and releases resources
func (ec *EnvCache) Close() {
	if ec.cache != nil {
		ec.cache.Stop()
	}
}
