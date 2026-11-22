package settings

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
)

// MaxLogRetentionDays bounds log_retention_days. It matches the audit-log
// retention bound so operators cannot accidentally disable pruning with a
// zero or negative value.
const MaxLogRetentionDays int64 = 36500

// ValidateLogRetentionDays accepts zero (keep logs forever) or a positive
// number of days. Negative values are rejected rather than silently disabling
// pruning, so a typo cannot hide unbounded growth.
func ValidateLogRetentionDays(days int64) error {
	if days < 0 || days > MaxLogRetentionDays {
		return fmt.Errorf("log_retention_days must be an integer between 0 and %d (0 keeps logs forever)", MaxLogRetentionDays)
	}
	return nil
}

// LogRetentionDays resolves an environment override first, then the global
// setting, then DefaultLogRetentionDays. Invalid stored rows are skipped so a
// malformed direct database edit cannot stop retention or shorten it to zero.
func (conf *Settings) LogRetentionDays(envID uint) int64 {
	scopes := []uint{NoEnvironmentID}
	if envID != NoEnvironmentID {
		scopes = append(scopes, envID)
	}
	var values []SettingValue
	if err := conf.DB.Where("service = ? AND name = ? AND environment_id IN ?", config.ServiceTLS, LogRetentionDays, scopes).
		Order("environment_id DESC, id ASC").Find(&values).Error; err != nil {
		return DefaultLogRetentionDays
	}
	for _, value := range values {
		if value.Type != TypeInteger || ValidateLogRetentionDays(value.Integer) != nil {
			continue
		}
		return value.Integer
	}
	return DefaultLogRetentionDays
}
