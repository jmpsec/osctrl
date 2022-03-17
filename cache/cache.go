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
	HashKeyResult = types.ResultLog
	// HashKeyStatus to be used as hash-key to keep status logs
	HashKeyStatus = types.StatusLog
	// HashKeyQuery to be used as hash-key to keep query logs
	HashKeyQuery = types.QueryLog
)

// RedisManager have access to cached data
type RedisManager struct {
	Config *JSONConfigurationRedis
	Client *redis.Client
}

// JSONConfigurationRedis to hold all redis configuration values
type JSONConfigurationRedis struct {
	Host                  string `json:"host"`
	Port                  string `json:"port"`
	Password              string `json:"password"`
	DB                    int    `json:"db"`
	StatusExpirationHours int    `json:"status_exp_hours"`
	ResultExpirationHours int    `json:"result_exp_hours"`
	QueryExpirationHours  int    `json:"query_exp_hours"`
}

// CachedQueryWriteData to store in cache query logs
type CachedQueryWriteData struct {
	UnixTime       int    `json:"unixTime"`
	HostIdentifier string `json:"hostIdentifier"`
	QueryData      types.QueryWriteData
}

// CachedStatusLogs to parse cached status logs
type CachedStatusLogs map[string][]types.LogStatusData

// CachedResultLogs to parse cached result logs
type CachedResultLogs map[string][]types.LogResultData

// CachedQueryLogs to parse cached query logs

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
func (r *RedisManager) GetStatusLogs(hostID, env string) (map[string][]byte, error) {
	return r.GetLogs(types.StatusLog, hostID, env)
}

// StatusLogs to retrieve cached status logs
func (r *RedisManager) StatusLogs(hostID, env string, secs int64) ([]types.LogStatusData, error) {
	data, err := r.GetStatusLogs(hostID, env)
	if err != nil {
		return []types.LogStatusData{}, fmt.Errorf("error getting logs - %v", err)
	}
	var result []types.LogStatusData
	for _, v := range data {
		var logs []types.LogStatusData
		if err := json.Unmarshal(v, &logs); err != nil {
			return result, fmt.Errorf("error parsing logs - %v", err)
		}
		result = append(result, logs...)
	}
	return result, nil
}

// GetLogs to retrieve logs generically
func (r *RedisManager) GetLogs(logType, hostID, envOrName string) (map[string][]byte, error) {
	var keyMatch string
	switch logType {
	case types.StatusLog:
		keyMatch = GenStatusMatch(hostID, envOrName)
	case types.ResultLog:
		keyMatch = GenResultMatch(hostID, envOrName)
	case types.QueryLog:
		keyMatch = GenQueryMatch(hostID, envOrName)
		if hostID == "" {
			keyMatch = GenQueryNameMatch(envOrName)
		}
	}
	ctx := context.TODO()
	iter := r.Client.Scan(ctx, 0, keyMatch, 0).Iterator()
	mappedData := make(map[string][]byte)
	for iter.Next(ctx) {
		mapKey := iter.Val()
		keyVal, err := r.Client.Get(ctx, mapKey).Result()
		if err != nil {
			return mappedData, fmt.Errorf("error retrieving key for %s - %v", logType, err)
		}
		mappedData[mapKey] = []byte(keyVal)
	}
	if err := iter.Err(); err != nil {
		return mappedData, fmt.Errorf("error iterating %s - %v", logType, err)
	}
	return mappedData, nil
}

// GetResultLogs to retrieve cached result logs
func (r *RedisManager) GetResultLogs(hostID, env string) (map[string][]byte, error) {
	return r.GetLogs(types.ResultLog, hostID, env)
}

// HResultLogs to retrieve cached status logs
func (r *RedisManager) ResultLogs(hostID, env string, secs int64) ([]types.LogResultData, error) {
	data, err := r.GetResultLogs(hostID, env)
	if err != nil {
		return []types.LogResultData{}, fmt.Errorf("error getting logs - %v", err)
	}
	var result []types.LogResultData
	for _, v := range data {
		var logs []types.LogResultData
		if err := json.Unmarshal(v, &logs); err != nil {
			return result, fmt.Errorf("error parsing logs - %v", err)
		}
		result = append(result, logs...)
	}
	return result, nil
}

// GetQueryLogs to retrieve cached query logs
func (r *RedisManager) GetQueryLogs(hostID, name string) (map[string][]byte, error) {
	return r.GetLogs(types.QueryLog, hostID, name)
}

// GetQueryNameLogs to retrieve cached query logs only by query name
func (r *RedisManager) GetQueryNameLogs(name string) (map[string][]byte, error) {
	return r.GetLogs(types.QueryLog, "", name)
}

// HQueryLogs to retrieve cached query logs
func (r *RedisManager) QueryLogs(name string) ([]CachedQueryWriteData, error) {
	var result []CachedQueryWriteData
	queryMap, err := r.GetQueryNameLogs(name)
	if err != nil {
		return result, fmt.Errorf("GetQueryNameLogs: %s", err)
	}
	for k, q := range queryMap {
		// Split key into fields
		name, hostId, unixtime := ParseQueryKey(k)
		// Parse raw logs
		var queryData types.QueryWriteData
		if err := json.Unmarshal(q, &queryData); err != nil {
			return result, fmt.Errorf("error parsing logs - %v", err)
		}
		// Verify query name matches
		if queryData.Name != name {
			return result, fmt.Errorf("query name does not match: %s != %s", queryData.Name, name)
		}
		rr := CachedQueryWriteData{
			UnixTime:       unixtime,
			HostIdentifier: hostId,
			QueryData:      queryData,
		}
		result = append(result, rr)
	}
	return result, nil
}

// SetLogs to write logs to cache
func (r *RedisManager) SetLogs(logType, hostID, envOrName string, data []byte) error {
	var hKey string
	var tExpire time.Duration
	switch logType {
	case types.StatusLog:
		hKey = GenStatusKey(hostID, envOrName)
		tExpire = time.Hour * time.Duration(r.Config.StatusExpirationHours)
	case types.ResultLog:
		hKey = GenResultKey(hostID, envOrName)
		tExpire = time.Hour * time.Duration(r.Config.ResultExpirationHours)
	case types.QueryLog:
		hKey = GenQueryKey(hostID, envOrName)
		tExpire = time.Hour * time.Duration(r.Config.QueryExpirationHours)
	}
	ctx := context.Background()
	if err := r.Client.Set(ctx, hKey, data, tExpire).Err(); err != nil {
		return fmt.Errorf("%s Set: %s", logType, err)
	}
	return nil
}

// SetStatusLogs to write status to cache
func (r *RedisManager) SetStatusLogs(hostID, env string, data []byte) error {
	return r.SetLogs(types.StatusLog, hostID, env, data)
}

// SetResultLogs to write result logs to cache
func (r *RedisManager) SetResultLogs(hostID, env string, data []byte) error {
	return r.SetLogs(types.ResultLog, hostID, env, data)
}

// SetQueryLogs to write query logs to cache
func (r *RedisManager) SetQueryLogs(hostID, name string, data []byte) error {
	return r.SetLogs(types.QueryLog, hostID, name, data)
}
