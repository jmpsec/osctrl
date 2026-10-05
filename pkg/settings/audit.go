package settings

import (
	"errors"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"gorm.io/gorm"
)

const AuditLogRetentionDays = "audit_log_retention_days"
const DefaultAuditLogRetentionDays int64 = 90

func ValidateAuditLogRetentionDays(days int64) error {
	if days < 1 || days > 36500 {
		return fmt.Errorf("audit_log_retention_days must be between 1 and 36500")
	}
	return nil
}

// AuditLogRetentionDays is shared by all services' audit rows. Invalid settings
// and database failures stop pruning rather than applying a shorter fallback.
func (conf *Settings) AuditLogRetentionDays() (int64, error) {
	value, err := conf.RetrieveValue(config.ServiceAPI, AuditLogRetentionDays, NoEnvironmentID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DefaultAuditLogRetentionDays, nil
	}
	if err != nil {
		return 0, err
	}
	if value.Type != TypeInteger {
		return 0, fmt.Errorf("audit retention must be an integer")
	}
	return value.Integer, ValidateAuditLogRetentionDays(value.Integer)
}
