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
	"github.com/jmpsec/osctrl/pkg/config"
)

// Structure to keep all SAML related data
type samlThings struct {
	RootURL        *url.URL
	IdpMetadataURL *url.URL
	IdpMetadata    *saml.EntityDescriptor
	KeyPair        tls.Certificate
}

// Function to initialize variables when using SAML for authentication
func keypairSAML(config config.YAMLConfigurationSAML) (samlThings, error) {
	var data samlThings
	var err error
	data.KeyPair, err = tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		return data, fmt.Errorf("loadX509KeyPair %w", err)
	}
	data.KeyPair.Leaf, err = x509.ParseCertificate(data.KeyPair.Certificate[0])
	if err != nil {
		return data, fmt.Errorf("parseCertificate %w", err)
	}
	data.IdpMetadataURL, err = url.Parse(config.MetaDataURL)
	if err != nil {
		return data, fmt.Errorf("parse MetadataURL %w", err)
	}
	data.IdpMetadata, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *data.IdpMetadataURL)
	if err != nil {
		return data, fmt.Errorf("fetch Metadata %w", err)
	}
	data.RootURL, err = url.Parse(config.RootURL)
	if err != nil {
		return data, fmt.Errorf("parse RootURL %w", err)
	}
	return data, nil
}
