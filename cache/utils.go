package cache

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PrepareAddr to generate redis connection string
func PrepareAddr(config JSONConfigurationRedis) string {
	return fmt.Sprintf("%s:%s", config.Host, config.Port)
}

// GenStatusKey to format the key to store status logs
func GenStatusKey(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%s:%d", HashKeyStatus, hostID, env, time.Now().UnixMilli())
}

// GenStatusMatch to format the match expression to scan status logs
func GenStatusMatch(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%s:*", HashKeyStatus, hostID, env)
}

// GenResultKey to format the key to store result logs
func GenResultKey(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%s:%d", HashKeyResult, hostID, env, time.Now().UnixMilli())
}

// GenResultMatch to format the match expression to scan result logs
func GenResultMatch(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%s:*", HashKeyResult, hostID, env)
}

// GenQueryKey to format the key to store query logs
func GenQueryKey(hostID, name string) string {
	return fmt.Sprintf("%s:%s:%s:%d", HashKeyQuery, name, hostID, time.Now().UnixMilli())
}

// GenQueryMatch to format the match expression to scan query logs
func GenQueryMatch(hostID, name string) string {
	return fmt.Sprintf("%s:%s:%s:*", HashKeyQuery, name, hostID)
}

// GenQueryNameMatch to format the match expression to scan for completed queries
func GenQueryNameMatch(name string) string {
	return fmt.Sprintf("%s:%s:*", HashKeyQuery, name)
}

// ParseQueryKey to parse the key used to cache queries
func ParseQueryKey(key string) (string, string, int) {
	parsed := strings.Split(key, ":")
	// parsed[1] is query name
	queryName := parsed[1]
	// parsed[2] is hostIdentifier
	hostIdentifier := parsed[2]
	// parsed[3] is unixtime
	i, err := strconv.Atoi(parsed[3])
	if err != nil {
		i = int(time.Now().Unix())
	}
	return queryName, hostIdentifier, i
}
