package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestLoadingSettingsDoesNotSeedRefreshEnvs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	mgr := settings.NewSettings(db)

	require.NoError(t, loadingSettings(mgr, &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{},
		Logger:  &config.YAMLConfigurationLogger{},
		Carver:  &config.YAMLConfigurationCarver{},
	}))

	_, err = mgr.RetrieveValue(config.ServiceAPI, "refresh_envs", settings.NoEnvironmentID)
	require.Error(t, err)
}
