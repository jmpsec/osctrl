package cache

import (
	"context"

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
	ctx := context.TODO()
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
		return nil, err
	}
	return rm, nil
}
