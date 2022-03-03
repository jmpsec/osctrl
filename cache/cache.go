package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"
)

const (
	// RedisKey to identify the configuration JSON key
	RedisKey = "redis"
	// StatusExpiration in hours to expire entries for status logs
	StatusExpiration = 24
	// ResultsExpiration in hours to expire entries for result logs
	ResultExpiration = 24
	// QueryExpiration in hours to expire entries for query logs
	QueryExpiration = 24
	// HashKeyResult to be used as hash-key to keep result logs
	HashKeyResult = "result"
	// HashKeyStatus to be used as hash-key to keep status logs
	HashKeyStatus = "status"
	// HashKeyQuery to be used as hash-key to keep query logs
	HashKeyQuery = "query"
)

// RedisManager have access to cached data
type RedisManager struct {
	Config *JSONConfigurationRedis
	Client *redis.Client
}

// JSONConfigurationRedis to hold all redis configuration values
type JSONConfigurationRedis struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
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
	dbRaw := viper.Sub(key)
	if err := dbRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// GetRedis to get redis client ready
func (rm *RedisManager) GetRedis() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     PrepareAddr(*rm.Config),
		Password: rm.Config.Password,
		DB:       rm.Config.DB,
	})
	return client
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

// GetStatusLogs to retrieve cached status logs
func (r *RedisManager) GetStatusLogs(hostID, env string) ([]byte, error) {
	return []byte{}, nil
}

// StatusLogs to retrieve cached status logs
func (r *RedisManager) StatusLogs(hostID, env string, secs int64) ([]types.LogStatusData, error) {
	data, err := r.GetStatusLogs(hostID, env)
	if err != nil {
		return []types.LogStatusData{}, fmt.Errorf("error getting logs - %v", err)
	}
	var logs []types.LogStatusData
	if err := json.Unmarshal(data, &logs); err != nil {
		return []types.LogStatusData{}, fmt.Errorf("error parsing logs - %v", err)
	}
	return logs, nil
}

// GetResultLogs to retrieve cached result logs
func (r *RedisManager) GetResultLogs(hostID, env string) ([]byte, error) {
	return []byte{}, nil
}

// HResultLogs to retrieve cached status logs
func (r *RedisManager) ResultLogs(hostID, env string, secs int64) ([]types.LogResultData, error) {
	data, err := r.GetResultLogs(hostID, env)
	if err != nil {
		return []types.LogResultData{}, fmt.Errorf("error getting logs - %v", err)
	}
	var logs []types.LogResultData
	if err := json.Unmarshal(data, &logs); err != nil {
		return []types.LogResultData{}, fmt.Errorf("error parsing logs - %v", err)
	}
	return logs, nil
}

// GetQueryLogs to retrieve cached query logs
func (r *RedisManager) GetQueryLogs(hostID, name string) ([]byte, error) {
	ctx := context.TODO()
	prefix := GenQueryPrefix(hostID, name)
	iter := r.Client.HScan(ctx, HashKeyQuery, 0, prefix, 0).Iterator()
	result := []byte{}
	for iter.Next(ctx) {
		result = append(result, []byte(iter.Val())...)
	}
	if err := iter.Err(); err != nil {
		return []byte{}, fmt.Errorf("error iterating results - %v", err)
	}
	return result, nil
}

// HQueryLogs to retrieve cached query logs
func (r *RedisManager) QueryLogs(name string) ([]CachedQueryWriteData, error) {
	return []CachedQueryWriteData{}, nil
}

// SetLogs to write logs to cache
func (r *RedisManager) SetLogs(logType, hostID, env string, data []byte) error {
	switch logType {
	case types.StatusLog:
		return r.SetStatusLogs(hostID, env, data)
	case types.ResultLog:
		return r.SetResultLogs(hostID, env, data)
	}
	return nil
}

// SetStatusLogs to write status to cache
func (r *RedisManager) SetStatusLogs(hostID, env string, data []byte) error {
	ctx := context.Background()
	key := GenStatusKey(hostID, env)
	if err := r.Client.HSet(ctx, HashKeyStatus, key, data).Err(); err != nil {
		return fmt.Errorf("SetStatusLogs HSet: %s", err)
	}
	if err := r.Client.Expire(ctx, key, time.Hour*StatusExpiration).Err(); err != nil {
		return fmt.Errorf("SetStatusLogs Expire: %s", err)
	}
	return nil
}

// SetResultLogs to write result logs to cache
func (r *RedisManager) SetResultLogs(hostID, env string, data []byte) error {
	ctx := context.Background()
	key := GenResultKey(hostID, env)
	if err := r.Client.HSet(ctx, HashKeyResult, key, data).Err(); err != nil {
		return fmt.Errorf("SetResultLogs HSet: %s", err)
	}
	if err := r.Client.Expire(ctx, key, time.Hour*ResultExpiration).Err(); err != nil {
		return fmt.Errorf("SetResultLogs Expire: %s", err)
	}
	return nil
}

// SetQueryLogs to write query logs to cache
func (r *RedisManager) SetQueryLogs(hostID, name string, data []byte) error {
	ctx := context.Background()
	key := GenQueryKey(hostID, name)
	if err := r.Client.HSet(ctx, HashKeyQuery, key, data).Err(); err != nil {
		return fmt.Errorf("SetQueryLogs HSet: %s", err)
	}
	if err := r.Client.Expire(ctx, key, time.Hour*QueryExpiration).Err(); err != nil {
		return fmt.Errorf("SetQueryLogs Expire: %s", err)
	}
	return nil
}
