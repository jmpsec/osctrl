package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Function to load the configuration file
func loadJWTConfiguration(file string) (types.JSONConfigurationJWT, error) {
	var cfg types.JSONConfigurationJWT
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// JWT values
	jwtRaw := viper.Sub(settings.AuthJWT)
	if jwtRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", settings.AuthJWT, file)
	}
	if err := jwtRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
