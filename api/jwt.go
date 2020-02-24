package main

import (
	"log"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"
)

// Function to load the configuration file
func loadJWTConfiguration(file string) (types.JSONConfigurationJWT, error) {
	var cfg types.JSONConfigurationJWT
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// JWT values
	headersRaw := viper.Sub(settings.AuthJWT)
	err = headersRaw.Unmarshal(&cfg)
	if err != nil {
		return cfg, err
	}

	// No errors!
	return cfg, nil
}
