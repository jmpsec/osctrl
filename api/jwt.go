package main

import (
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
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
	headersRaw := viper.Sub(settings.AuthJWT)
	if err := headersRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
