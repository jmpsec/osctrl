package environments

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/cache"
)

const (
	cacheName = "environments"
	// envCacheTTL is the maximum time a TLSEnvironment can sit in the
	// EnvCache before the next request refetches from the database.
	//
	// osctrl-tls holds this cache; osctrl-api mutates env rows in the
	// same DB from a different process. There is no IPC channel between
	// the two, so envCache invalidation is TTL-based — the TTL bounds
	// the window during which enroll-secret rotations, env deletions,
	// or config-PATCH changes can be served stale by osctrl-tls.
	//
	// Kept at the historical 2h cleanup interval; operators who need
	// faster invalidation can rotate via `osctrl-tls` restart or tune
	// this constant locally.
	envCacheTTL = 2 * time.Hour
)

// EnvCache provides cached access to TLS environments
type EnvCache struct {
	// The cache itself, storing Environment objects
	cache *cache.MemoryCache[TLSEnvironment]

	// Reference to the environment manager for cache misses
	envs EnvManager
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

// GetByUUID retrieves an environment by UUID, using cache when available
func (ec *EnvCache) GetByUUID(ctx context.Context, uuid string) (TLSEnvironment, error) {
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
	ec.cache.Delete(ctx, uuid)
}

// InvalidateAll clears the entire cache. Used on bulk operations or
// after operator-driven secret rotations.
func (ec *EnvCache) InvalidateAll(ctx context.Context) {
	ec.cache.Clear(ctx)
}

// UpdateEnvInCache updates an environment in the cache
func (ec *EnvCache) UpdateEnvInCache(ctx context.Context, env TLSEnvironment) {
	ec.cache.Set(ctx, env.UUID, env, envCacheTTL)
}

// Close stops the cleanup goroutine and releases resources
func (ec *EnvCache) Close() {
	if ec.cache != nil {
		ec.cache.Stop()
	}
}
