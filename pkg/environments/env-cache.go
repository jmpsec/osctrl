package environments

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/cache"
)

// EnvCache provides cached access to TLS environments
type EnvCache struct {
	// The cache itself, storing Environment objects
	cache *cache.MemoryCache[TLSEnvironment]

	// Reference to the environment manager for cache misses
	envs EnvironmentManager
}

// NewEnvCache creates a new environment cache
func NewEnvCache(envs EnvironmentManager) *EnvCache {
	// Create a new cache with a 10-minute cleanup interval
	envCache := cache.NewMemoryCache(
		cache.WithCleanupInterval[TLSEnvironment](2 * time.Hour),
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

	ec.cache.Set(ctx, uuid, env, 2*time.Hour)

	return env, nil
}

// InvalidateEnv removes a specific environment from the cache
func (ec *EnvCache) InvalidateEnv(ctx context.Context, uuid string) {
	ec.cache.Delete(ctx, uuid)
}

// InvalidateAll clears the entire cache
func (ec *EnvCache) InvalidateAll(ctx context.Context) {
	ec.cache.Clear(ctx)
}

// UpdateEnvInCache updates an environment in the cache
func (ec *EnvCache) UpdateEnvInCache(ctx context.Context, env TLSEnvironment) {
	ec.cache.Set(ctx, env.UUID, env, 2*time.Hour)
}
