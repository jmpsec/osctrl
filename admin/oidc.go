package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/settings"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// JSONConfigurationOIDC to keep all OIDC details for auth
type JSONConfigurationOIDC struct {
	IssuerURL         string   `json:"issuerurl"`
	ClientID          string   `json:"clientid"`
	ClientSecret      string   `json:"clientsecret"`
	RedirectURL       string   `json:"redirecturl"`
	Scope             []string `json:"scope"`
	Nonce             string   `json:"nonce"`
	ResponseType      string   `json:"responsetype"`
	AuthorizationCode string   `json:"authorizationcode"`
}

// Function to load the configuration file
func loadOIDC(file string) (JSONConfigurationOIDC, error) {
	var cfg JSONConfigurationOIDC
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// OAuth values
	oauthRaw := viper.Sub(settings.AuthOIDC)
	if oauthRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", settings.AuthOIDC, file)
	}
	if err := oauthRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
