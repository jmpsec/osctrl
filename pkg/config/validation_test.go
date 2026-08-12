package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateTLSConfigValuesAcceptsKafkaAndMultipleLoggers(t *testing.T) {
	err := ValidateTLSConfigValues(TLSConfiguration{
		Service: YAMLConfigurationService{Auth: AuthNone},
		Logger:  &YAMLConfigurationLogger{Types: []string{LoggingDB, LoggingKafka}},
		Carver:  &YAMLConfigurationCarver{Type: CarverDB},
	})
	if err != nil {
		t.Fatalf("expected kafka and multiple logger types to validate: %v", err)
	}
}

func TestValidateTLSConfigValuesRejectsInvalidMultipleLogger(t *testing.T) {
	err := ValidateTLSConfigValues(TLSConfiguration{
		Service: YAMLConfigurationService{Auth: AuthNone},
		Logger:  &YAMLConfigurationLogger{Types: []string{LoggingDB, "bogus"}},
		Carver:  &YAMLConfigurationCarver{Type: CarverDB},
	})
	if err == nil {
		t.Fatalf("expected invalid logger type to fail validation")
	}
}

func TestValidateRateLimitsRejectsInvalidValues(t *testing.T) {
	cfg := YAMLConfigurationRateLimits{
		Enroll: YAMLConfigurationRateLimit{
			Burst:      0,
			Period:     time.Minute,
			EvictAfter: time.Minute,
			RetryAfter: 60,
		},
	}

	err := ValidateRateLimits(cfg, "enroll")
	if err == nil {
		t.Fatal("expected invalid rate limit to fail validation")
	}
	if !strings.Contains(err.Error(), "enroll burst must be greater than 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRateLimitsAcceptsDefaults(t *testing.T) {
	if err := ValidateRateLimits(DefaultRateLimits(), "login", "preAuth", "serviceConfigApply", "enroll"); err != nil {
		t.Fatalf("default rate limits should validate: %v", err)
	}
}
