package cache

import (
	"fmt"
	"time"
)

// PrepareAddr to generate redis connection string
func PrepareAddr(config JSONConfigurationRedis) string {
	return fmt.Sprintf("%s:%s", config.Host, config.Port)
}

// GenStatusKey to format the key to store status logs
func GenStatusKey(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%d", hostID, env, time.Now().UnixMilli())
}

// GenStatusPrefix to format the prefix to scan status logs
func GenStatusPrefix(hostID, env string) string {
	return fmt.Sprintf("%s:%s:*", hostID, env)
}

// GenResultKey to format the key to store result logs
func GenResultKey(hostID, env string) string {
	return fmt.Sprintf("%s:%s:%d", hostID, env, time.Now().UnixMilli())
}

// GenResultPrefix to format the prefix to scan result logs
func GenResultPrefix(hostID, env string) string {
	return fmt.Sprintf("%s:%s:*", hostID, env)
}

// GenQueryKey to format the key to store query logs
func GenQueryKey(hostID, name string) string {
	return fmt.Sprintf("%s:%s:%d", name, hostID, time.Now().UnixMilli())
}

// GenQueryPrefix to format the prefix to scan query logs
func GenQueryPrefix(hostID, name string) string {
	return fmt.Sprintf("%s:%s:*", name, hostID)
}
