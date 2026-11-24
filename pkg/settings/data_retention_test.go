package settings

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestDataRetentionDefaults(t *testing.T) {
	conf := &Settings{DB: setupSettingsTestDB(t)}
	require.Equal(t, DefaultSantaEventRetentionDays, conf.SantaEventRetentionDays())
	require.Equal(t, DefaultCarveRetentionDays, conf.CarveRetentionDays())
	require.Equal(t, DefaultQueryMetadataRetentionDays, conf.QueryMetadataRetentionDays())
	require.Equal(t, DefaultSessionRetentionDays, conf.SessionRetentionDays())
}

func TestDataRetentionResolutionAndValidation(t *testing.T) {
	conf := &Settings{DB: setupSettingsTestDB(t)}

	require.NoError(t, conf.NewIntegerValue(config.ServiceAPI, CarveRetentionDays, 90, NoEnvironmentID))
	require.Equal(t, int64(90), conf.CarveRetentionDays())

	require.NoError(t, conf.SetInteger(0, config.ServiceAPI, CarveRetentionDays, NoEnvironmentID))
	require.Equal(t, int64(0), conf.CarveRetentionDays())

	require.Error(t, conf.SetInteger(-1, config.ServiceAPI, CarveRetentionDays, NoEnvironmentID))
	require.Error(t, conf.SetInteger(MaxRetentionDays+1, config.ServiceAPI, CarveRetentionDays, NoEnvironmentID))
	require.NoError(t, conf.SetInteger(MaxRetentionDays, config.ServiceAPI, CarveRetentionDays, NoEnvironmentID))

	// Invalid legacy rows fall back to the default instead of disabling pruning.
	require.NoError(t, conf.DB.Model(&SettingValue{}).
		Where("service = ? AND name = ?", config.ServiceAPI, CarveRetentionDays).
		Update("integer", -5).Error)
	require.Equal(t, DefaultCarveRetentionDays, conf.CarveRetentionDays())
}

func TestValidateIntegerSettingDataRetention(t *testing.T) {
	for _, name := range []string{SantaEventRetentionDays, CarveRetentionDays, QueryMetadataRetentionDays, SessionRetentionDays} {
		require.NoError(t, ValidateIntegerSetting(config.ServiceAPI, name, 0))
		require.NoError(t, ValidateIntegerSetting(config.ServiceAPI, name, MaxRetentionDays))
		require.Error(t, ValidateIntegerSetting(config.ServiceAPI, name, -1))
		require.Error(t, ValidateIntegerSetting(config.ServiceAPI, name, MaxRetentionDays+1))
	}
}
