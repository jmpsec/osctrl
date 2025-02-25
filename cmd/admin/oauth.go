package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// JSONConfigurationOAuth to keep all OAuth details for auth
type JSONConfigurationOAuth struct {
	ClientID     string   `json:"clientid"`
	ClientSecret string   `json:"clientsecret"`
	RedirectURL  string   `json:"redirecturl"`
	Scopes       []string `json:"scopes"`
	EndpointURL  string   `json:"endpointurl"`
}

// Function to load the configuration file
func loadOAuth(file string) (JSONConfigurationOAuth, error) {
	var cfg JSONConfigurationOAuth
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// OAuth values
	oauthRaw := viper.Sub(settings.AuthOAuth)
	if oauthRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", settings.AuthOAuth, file)
	}
	if err := oauthRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
