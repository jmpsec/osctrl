package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestLoadingSettingsDefaultsAcceleratedSecondsToFive(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	mgr := settings.NewSettings(db)

	require.NoError(t, loadingSettings(mgr, &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{},
		Logger:  &config.YAMLConfigurationLogger{},
		Carver:  &config.YAMLConfigurationCarver{},
	}))

	got, err := mgr.GetInteger(config.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironmentID)
	require.NoError(t, err)
	require.Equal(t, int64(5), got)
}
