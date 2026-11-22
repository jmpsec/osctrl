package settings

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestLogRetentionDaysResolution(t *testing.T) {
	conf := &Settings{DB: setupSettingsTestDB(t)}

	// Missing setting: the safe default applies.
	require.Equal(t, DefaultLogRetentionDays, conf.LogRetentionDays(NoEnvironmentID))
	require.Equal(t, DefaultLogRetentionDays, conf.LogRetentionDays(7))

	// Global value applies to every environment.
	require.NoError(t, conf.NewIntegerValue(config.ServiceTLS, LogRetentionDays, 30, NoEnvironmentID))
	require.Equal(t, int64(30), conf.LogRetentionDays(NoEnvironmentID))
	require.Equal(t, int64(30), conf.LogRetentionDays(7))

	// Environment override wins over the global value.
	require.NoError(t, conf.NewIntegerValue(config.ServiceTLS, LogRetentionDays, 7, 7))
	require.Equal(t, int64(7), conf.LogRetentionDays(7))
	require.Equal(t, int64(30), conf.LogRetentionDays(8))

	// Invalid legacy rows are skipped rather than disabling retention.
	require.NoError(t, conf.DB.Model(&SettingValue{}).
		Where("service = ? AND name = ? AND environment_id = ?", config.ServiceTLS, LogRetentionDays, 7).
		Update("integer", -1).Error)
	require.Equal(t, int64(30), conf.LogRetentionDays(7))

	// An explicit zero means keep logs forever for that environment.
	require.NoError(t, conf.SetInteger(0, config.ServiceTLS, LogRetentionDays, 7))
	require.Equal(t, int64(0), conf.LogRetentionDays(7))
	require.Equal(t, int64(30), conf.LogRetentionDays(8))
}

func TestLogRetentionDaysValidation(t *testing.T) {
	conf := &Settings{DB: setupSettingsTestDB(t)}

	require.Error(t, conf.NewIntegerValue(config.ServiceTLS, LogRetentionDays, -1, NoEnvironmentID))
	require.Error(t, conf.NewIntegerValue(config.ServiceTLS, LogRetentionDays, MaxLogRetentionDays+1, NoEnvironmentID))
	require.NoError(t, conf.NewIntegerValue(config.ServiceTLS, LogRetentionDays, 1, NoEnvironmentID))
	require.NoError(t, conf.SetInteger(0, config.ServiceTLS, LogRetentionDays, NoEnvironmentID))
	require.NoError(t, conf.SetInteger(365, config.ServiceTLS, LogRetentionDays, NoEnvironmentID))
	require.Equal(t, int64(365), conf.LogRetentionDays(NoEnvironmentID))

	require.Error(t, ValidateLogRetentionDays(-1))
	require.Error(t, ValidateLogRetentionDays(MaxLogRetentionDays+1))
	require.NoError(t, ValidateLogRetentionDays(0))
	require.NoError(t, ValidateLogRetentionDays(1))
	require.NoError(t, ValidateLogRetentionDays(MaxLogRetentionDays))
}
