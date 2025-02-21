package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// JSONConfigurationSAML to keep all SAML details for auth
type JSONConfigurationSAML struct {
	CertPath     string `json:"certpath"`
	KeyPath      string `json:"keypath"`
	MetaDataURL  string `json:"metadataurl"`
	RootURL      string `json:"rooturl"`
	LoginURL     string `json:"loginurl"`
	LogoutURL    string `json:"logouturl"`
	JITProvision bool   `json:"jitprovision"`
}

// Structure to keep all SAML related data
type samlThings struct {
	RootURL        *url.URL
	IdpMetadataURL *url.URL
	IdpMetadata    *saml.EntityDescriptor
	KeyPair        tls.Certificate
}

// Function to load the configuration file
func loadSAML(file string) (JSONConfigurationSAML, error) {
	var cfg JSONConfigurationSAML
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// SAML values
	samlRaw := viper.Sub(settings.AuthSAML)
	if samlRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", settings.AuthSAML, file)
	}
	if err := samlRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Verify SAML configuration
	if err := verifySAML(cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}

// Function to verify SAML configuration
func verifySAML(cfg JSONConfigurationSAML) error {
	if cfg.CertPath == "" {
		return fmt.Errorf("Missing CertPath")
	}
	if cfg.KeyPath == "" {
		return fmt.Errorf("Missing KeyPath")
	}
	if cfg.MetaDataURL == "" {
		return fmt.Errorf("Missing MetaDataURL")
	}
	if cfg.RootURL == "" {
		return fmt.Errorf("Missing RootURL")
	}
	if cfg.LoginURL == "" {
		return fmt.Errorf("Missing LoginURL")
	}
	if cfg.LogoutURL == "" {
		return fmt.Errorf("Missing LogoutURL")
	}
	return nil
}

// Function to initialize variables when using SAML for authentication
func keypairSAML(config JSONConfigurationSAML) (samlThings, error) {
	var data samlThings
	var err error
	data.KeyPair, err = tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		return data, fmt.Errorf("LoadX509KeyPair %v", err)
	}
	data.KeyPair.Leaf, err = x509.ParseCertificate(data.KeyPair.Certificate[0])
	if err != nil {
		return data, fmt.Errorf("ParseCertificate %v", err)
	}
	data.IdpMetadataURL, err = url.Parse(config.MetaDataURL)
	if err != nil {
		return data, fmt.Errorf("Parse MetadataURL %v", err)
	}
	data.IdpMetadata, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *data.IdpMetadataURL)
	if err != nil {
		return data, fmt.Errorf("Fetch Metadata %v", err)
	}
	data.RootURL, err = url.Parse(config.RootURL)
	if err != nil {
		return data, fmt.Errorf("Parse RootURL %v", err)
	}
	return data, nil
}

// Function to serve as login redirect
func loginSAML(w http.ResponseWriter, r *http.Request, samlConfig JSONConfigurationSAML) {
	http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
}
