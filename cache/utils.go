package cache

import (
	"fmt"
)

// PrepareAddr to generate redis connection string
func PrepareAddr(config JSONConfigurationRedis) string {
	return fmt.Sprintf("%s:%s", config.Host, config.Port)
}
