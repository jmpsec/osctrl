package config

import (
	"fmt"
)

// Valid values for authentication in configuration
var validAuth = map[string]bool{
	AuthNone: true,
}

// Valid values for logging in configuration
var validLogging = map[string]bool{
	LoggingNone:     true,
	LoggingStdout:   true,
	LoggingFile:     true,
	LoggingDB:       true,
	LoggingGraylog:  true,
	LoggingSplunk:   true,
	LoggingLogstash: true,
	LoggingKinesis:  true,
	LoggingS3:       true,
	LoggingElastic:  true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	CarverDB:    true,
	CarverLocal: true,
	CarverS3:    true,
}

// Helper to validate the TLS configuration values
func ValidateTLSConfigValues(cfg TLSConfiguration) error {
	// Check if values are valid
	if !validAuth[cfg.Service.Auth] {
		return fmt.Errorf("invalid auth method")
	}
	if !validLogging[cfg.Logger.Type] {
		return fmt.Errorf("invalid logging method")
	}
	if !validCarver[cfg.Carver.Type] {
		return fmt.Errorf("invalid carver method")
	}
	// No errors!
	return nil
}
