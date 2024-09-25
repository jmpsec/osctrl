package main

import (
	"github.com/jmpsec/osctrl/settings"
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
	if err := oauthRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
