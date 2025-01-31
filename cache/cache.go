package cache

import (
	"context"
	"fmt"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"
)

const (
	// RedisKey to identify the configuration JSON key
	RedisKey = "redis"
)

// RedisManager have access to cached data
type RedisManager struct {
	Config *JSONConfigurationRedis
	Client *redis.Client
}

// JSONConfigurationRedis to hold all redis configuration values
type JSONConfigurationRedis struct {
	Host             string `json:"host"`
	Port             string `json:"port"`
	Password         string `json:"password"`
	ConnectionString string `json:"connectionstring"`
	DB               int    `json:"db"`
	ConnRetry        int    `json:"connRetry"`
}

// CachedQueryWriteData to store in cache query logs
type CachedQueryWriteData struct {
	UnixTime       int    `json:"unixTime"`
	HostIdentifier string `json:"hostIdentifier"`
	QueryData      types.QueryWriteData
}

// LoadConfiguration to load the redis configuration file and assign to variables
func LoadConfiguration(file, key string) (JSONConfigurationRedis, error) {
	var config JSONConfigurationRedis
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}
	// Backend values
	redisRaw := viper.Sub(key)
	if redisRaw == nil {
		return config, fmt.Errorf("JSON key %s not found in %s", key, file)
	}
	if err := redisRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// GetRedis to get redis client ready
func (rm *RedisManager) GetRedis() *redis.Client {
	opt, err := redis.ParseURL(rm.Config.ConnectionString)
	if err != nil {
		//use current behavior
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

// CreateRedisManagerFile to initialize the redis manager struct from file
func CreateRedisManagerFile(file string) (*RedisManager, error) {
	redisConfig, err := LoadConfiguration(file, RedisKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to load redis configuration - %v", err)
	}
	return CreateRedisManager(redisConfig)
}

// CreateRedisManager to initialize the redis manager struct
func CreateRedisManager(config JSONConfigurationRedis) (*RedisManager, error) {
	rm := &RedisManager{}
	rm.Config = &config
	rm.Client = rm.GetRedis()
	if err := rm.Check(); err != nil {
		return nil, err
	}
	return rm, nil
}
