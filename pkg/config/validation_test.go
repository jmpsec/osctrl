package config

import "testing"

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
