package nodeconfig

import (
	"context"
	"errors"
	"time"

	redis "github.com/go-redis/redis/v8"
)

const (
	cacheTTL      = time.Hour
	cacheOpBudget = 250 * time.Millisecond
)

func cacheKey(nodeUUID string) string { return "osctrl:nodeconfig:" + nodeUUID }

// store is the cache the Manager uses; a Redis implementation backs it.
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
