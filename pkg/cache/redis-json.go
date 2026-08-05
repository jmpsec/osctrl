package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	redis "github.com/go-redis/redis/v8"
)

// RedisJSONCache stores typed JSON values in Redis under a fixed key prefix.
type RedisJSONCache[T any] struct {
	client *redis.Client
	prefix string
}

// NewRedisJSONCache creates a typed Redis-backed JSON cache.
func NewRedisJSONCache[T any](client *redis.Client, prefix string) *RedisJSONCache[T] {
	return &RedisJSONCache[T]{
		client: client,
		prefix: strings.TrimSuffix(prefix, ":"),
	}
}

// Get retrieves and decodes a value. ok=false means Redis had no value.
func (c *RedisJSONCache[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var zero T
	data, err := c.client.Get(ctx, c.cacheKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return zero, false, nil
		}
		return zero, false, err
	}

	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return zero, false, err
	}
	return value, true, nil
}

// Set encodes and stores a value. ttl<=0 stores without expiration.
func (c *RedisJSONCache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.cacheKey(key), data, ttl).Err()
}

// GetStale retrieves the cached value ignoring whether it has
// technically expired. Redis only returns a value if the key still
// exists; expired keys are deleted by Redis on read or by the
// background eviction, so "stale" here means "still present in Redis
// past the TTL we set". Callers use this as a last-resort fallback
// when the primary data source (e.g. the DB) is unavailable.
//
// Returns (value, true, nil) when the key exists regardless of its
// remaining TTL, and (zero, false, nil) when Redis does not have the
// key. Redis errors are returned as-is.
func (c *RedisJSONCache[T]) GetStale(ctx context.Context, key string) (T, bool, error) {
	return c.Get(ctx, key)
}

// Delete removes a cached value.
func (c *RedisJSONCache[T]) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.cacheKey(key)).Err()
}

func (c *RedisJSONCache[T]) cacheKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return c.prefix + ":" + key
}
