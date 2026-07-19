package environments

import (
	"context"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/cache"
)

const (
	cacheName                = "environments"
	redisEnvCacheName        = "osctrl:tls:environment"
	RedisEnvInvalidatePrefix = "envcache:invalidate:"
	// envCacheTTL is the maximum time a TLSEnvironment can sit in the
	// EnvCache before the next request refetches from the database.
	//
	// osctrl-tls holds this cache; osctrl-api mutates env rows in the
	// same DB from a different process. There is no IPC channel between
	// the two, so envCache invalidation is TTL-based — the TTL bounds
	// the window during which enroll-secret rotations, env deletions,
	// or config-PATCH changes can be served stale by osctrl-tls.
	//
	// 5 minutes: the fallback window if no invalidation signal is
	// received. With Redis-based invalidation wired in (see
	// SetInvalidationCheck), config PATCHes are picked up immediately;
	// this TTL only bounds the worst case (Redis down, API and TLS
	// can't communicate). 5m keeps DB load low while limiting staleness.
	envCacheTTL = 5 * time.Minute
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
	// the DB. Set via SetInvalidationCheck — typically a function
	// that checks a Redis key set by osctrl-api after a config PATCH.
	invalidationCheck func(ctx context.Context, uuid string) bool
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
// considered stale and the env is refetched from the DB. The typical
// implementation checks a Redis key that osctrl-api sets after
// mutating an env row (config PATCH, secret rotation, etc.).
func (ec *EnvCache) SetInvalidationCheck(fn func(ctx context.Context, uuid string) bool) {
	ec.invalidationCheck = fn
}

// GetByUUID retrieves an environment by UUID, using cache when available
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
			return TLSEnvironment{}, err
		}
		_ = ec.redisCache.Set(ctx, uuid, env, envCacheTTL)
		return env, nil
	}

	// Try to get from cache first
	if env, found := ec.cache.Get(ctx, uuid); found {
		return env, nil
	}

	// Not in cache, fetch from database
	env, err := ec.envs.GetByUUID(uuid)
	if err != nil {
		return TLSEnvironment{}, err
	}

	ec.cache.Set(ctx, uuid, env, envCacheTTL)

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
