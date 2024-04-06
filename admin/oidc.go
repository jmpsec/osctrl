package main

import (
	"log"

	"github.com/jmpsec/osctrl/settings"
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
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// OAuth values
	oauthRaw := viper.Sub(settings.AuthOIDC)
	if err := oauthRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
