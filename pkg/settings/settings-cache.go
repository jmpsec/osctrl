package settings

import (
	"context"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
)

const redisSettingsCacheName = "osctrl:tls:settings"

// settingsCacheDegradedTTL extends the cache TTL during a DB outage
// so the service keeps serving cached settings to osquery nodes.
// 60m matches the EnvCache degraded TTL for a consistent outage window.
const settingsCacheDegradedTTL = 60 * time.Minute

// RedisSettingsCache caches a service/env settings map in Redis.
type RedisSettingsCache struct {
	settings *Settings
	cache    *cache.RedisJSONCache[MapSettings]
	service  string
	envID    uint
	ttl      time.Duration
	dbHealth backend.DegradedReader
}

// NewRedisSettingsCache creates a Redis-backed cache for settings.GetMap.
func NewRedisSettingsCache(settings *Settings, client *redis.Client, service string, envID uint, ttl time.Duration) *RedisSettingsCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &RedisSettingsCache{
		settings: settings,
		cache:    cache.NewRedisJSONCache[MapSettings](client, redisSettingsCacheName),
		service:  service,
		envID:    envID,
		ttl:      ttl,
	}
}

// SetDBHealth wires a DB health monitor. When the monitor reports the
// database as degraded, GetMap serves a stale cached entry on a DB
// miss instead of returning an error, and writes during degradation
// use settingsCacheDegradedTTL. Pass nil to disable (the default).
func (c *RedisSettingsCache) SetDBHealth(h backend.DegradedReader) {
	c.dbHealth = h
}

// GetMap returns the cached settings map, refetching from DB on Redis miss/error.
func (c *RedisSettingsCache) GetMap(ctx context.Context) (MapSettings, error) {
	key := c.key()
	if cached, found, err := c.cache.Get(ctx, key); err == nil && found {
		return cached, nil
	} else if err != nil {
		_ = c.cache.Delete(ctx, key)
	}

	values, err := c.settings.GetMap(c.service, c.envID)
	if err != nil {
		if c.dbHealth != nil && c.dbHealth.IsDegraded() {
			if stale, found, _ := c.cache.GetStale(ctx, key); found {
				return stale, nil
			}
		}
		return MapSettings{}, err
	}
	ttl := c.ttl
	if c.dbHealth != nil && c.dbHealth.IsDegraded() {
		ttl = settingsCacheDegradedTTL
	}
	_ = c.cache.Set(ctx, key, values, ttl)
	return values, nil
}

// Invalidate removes the cached settings map.
func (c *RedisSettingsCache) Invalidate(ctx context.Context) error {
	return c.cache.Delete(ctx, c.key())
}

func (c *RedisSettingsCache) key() string {
	return fmt.Sprintf("%s:%d", c.service, c.envID)
}
