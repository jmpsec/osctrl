package cache

import (
	"context"
	"fmt"
	"strings"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/config"
)

const (
	// RedisKey to identify the configuration JSON key
	RedisKey = "redis"
)

// RedisManager have access to cached data
type RedisManager struct {
	Config *config.YAMLConfigurationRedis
	Client *redis.Client
}

// GetRedis to get redis client ready
func (rm *RedisManager) GetRedis() *redis.Client {
	opt, err := redis.ParseURL(rm.Config.ConnectionString)
	if err != nil {
		// use current behavior
		return redis.NewClient(&redis.Options{
			Addr:     PrepareAddr(*rm.Config),
			Password: rm.Config.Password,
			DB:       rm.Config.DB,
		})
	}
	return redis.NewClient(opt)
}

// Check to verify if connection is open and ready
func (rm *RedisManager) Check() error {
	return rm.CheckContext(context.TODO())
}

// CheckContext is Check with a caller-supplied context, so callers that need
// a bounded deadline (e.g. the health endpoint) are not left waiting forever
// on a blackholed connection.
func (rm *RedisManager) CheckContext(ctx context.Context) error {
	if err := rm.Client.Ping(ctx).Err(); err != nil {
		return err
	}
	return nil
}

// CreateRedisManager to initialize the redis manager struct
func CreateRedisManager(cfg config.YAMLConfigurationRedis) (*RedisManager, error) {
	rm := &RedisManager{}
	rm.Config = &cfg
	rm.Client = rm.GetRedis()
	if err := rm.Check(); err != nil {
		return nil, redisConnectionError(cfg, err)
	}
	return rm, nil
}

func redisConnectionError(cfg config.YAMLConfigurationRedis, err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "AUTH <password> called without any password configured") {
		if cfg.ConnectionString != "" {
			return fmt.Errorf("redis auth rejected: redis.connectionString includes credentials, but Redis has no password configured; remove credentials from redis.connectionString or configure a Redis password: %w", err)
		}
		return fmt.Errorf("redis auth rejected: redis.password is set, but Redis has no password configured; clear redis.password or configure a Redis password: %w", err)
	}
	return err
}
