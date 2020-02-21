package main

import (
	"log"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"
)

// Function to load the configuration file
func loadHeaders(file string) (types.JSONConfigurationHeaders, error) {
	var cfg types.JSONConfigurationHeaders
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// Header values
	headersRaw := viper.Sub(settings.AuthHeaders)
	err = headersRaw.Unmarshal(&cfg)
	if err != nil {
		return cfg, err
	}

	// No errors!
	return cfg, nil
}
