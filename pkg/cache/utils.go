package cache

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
)

// PrepareAddr to generate redis connection string
func PrepareAddr(cfg config.YAMLConfigurationRedis) string {
	return fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
}
