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
