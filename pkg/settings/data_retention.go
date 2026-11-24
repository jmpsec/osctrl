package settings

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
)

// Retention settings for data classes outside the database log pipeline.
const (
	// SantaEventRetentionDays bounds Santa execution and file-access events.
	SantaEventRetentionDays string = "santa_event_retention_days"
	// CarveRetentionDays bounds completed carve metadata, blocks, and stored
	// objects.
	CarveRetentionDays string = "carve_retention_days"
	// QueryMetadataRetentionDays bounds completed/expired distributed-query
	// metadata after their results have been retained or pruned.
	QueryMetadataRetentionDays string = "query_metadata_retention_days"
	// SessionRetentionDays bounds inactive console and file-explorer sessions
	// and their child command/request rows.
	SessionRetentionDays string = "session_retention_days"
)

// Defaults. Santa keeps its previous fixed 30-day window; the other classes
// default to "keep forever" so an upgrade never deletes data until an operator
// opts in.
const (
	DefaultSantaEventRetentionDays    int64 = 30
	DefaultCarveRetentionDays         int64 = 0
	DefaultQueryMetadataRetentionDays int64 = 0
	DefaultSessionRetentionDays       int64 = 0
)

// MaxRetentionDays bounds every data-retention setting.
const MaxRetentionDays int64 = 36500

// ValidateRetentionDays accepts zero (keep forever) or a positive number of
// days. Negative values are rejected rather than silently disabling pruning.
func ValidateRetentionDays(days int64) error {
	if days < 0 || days > MaxRetentionDays {
		return fmt.Errorf("retention must be an integer between 0 and %d (0 keeps data forever)", MaxRetentionDays)
	}
	return nil
}

func retentionDefault(name string) int64 {
	switch name {
	case SantaEventRetentionDays:
		return DefaultSantaEventRetentionDays
	case CarveRetentionDays:
		return DefaultCarveRetentionDays
	case QueryMetadataRetentionDays:
		return DefaultQueryMetadataRetentionDays
	case SessionRetentionDays:
		return DefaultSessionRetentionDays
	default:
		return 0
	}
}

func isDataRetentionSetting(name string) bool {
	switch name {
	case SantaEventRetentionDays, CarveRetentionDays, QueryMetadataRetentionDays, SessionRetentionDays:
		return true
	default:
		return false
	}
}

// RetentionDays resolves a global data-retention setting, falling back to the
// per-class default when absent or invalid.
func (conf *Settings) RetentionDays(name string) int64 {
	if !isDataRetentionSetting(name) {
		return 0
	}
	value, err := conf.RetrieveValue(config.ServiceAPI, name, NoEnvironmentID)
	if err != nil || value.Type != TypeInteger || ValidateRetentionDays(value.Integer) != nil {
		return retentionDefault(name)
	}
	return value.Integer
}

// SantaEventRetentionDays returns the configured Santa event window.
func (conf *Settings) SantaEventRetentionDays() int64 {
	return conf.RetentionDays(SantaEventRetentionDays)
}

// CarveRetentionDays returns the configured completed-carve window.
func (conf *Settings) CarveRetentionDays() int64 {
	return conf.RetentionDays(CarveRetentionDays)
}

// QueryMetadataRetentionDays returns the configured completed-query window.
func (conf *Settings) QueryMetadataRetentionDays() int64 {
	return conf.RetentionDays(QueryMetadataRetentionDays)
}

// SessionRetentionDays returns the configured inactive-session window.
func (conf *Settings) SessionRetentionDays() int64 {
	return conf.RetentionDays(SessionRetentionDays)
}
