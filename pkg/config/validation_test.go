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

func TestValidateTLSConfigValuesAcceptsHTTP(t *testing.T) {
	err := ValidateTLSConfigValues(TLSConfiguration{
		Service: YAMLConfigurationService{Auth: AuthNone},
		Logger:  &YAMLConfigurationLogger{Types: []string{LoggingHTTP}},
		Carver:  &YAMLConfigurationCarver{Type: CarverDB},
	})
	if err != nil {
		t.Fatalf("expected http logger type to validate: %v", err)
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

func TestValidateTLSConfigValuesRejectsLocalCarver(t *testing.T) {
	err := ValidateTLSConfigValues(TLSConfiguration{
		Service: YAMLConfigurationService{Auth: AuthNone},
		Carver:  &YAMLConfigurationCarver{Type: CarverLocal},
	})
	if err == nil || !strings.Contains(err.Error(), `carver type "local" is not supported`) {
		t.Fatalf("expected local carver to be rejected with a clear message, got %v", err)
	}
}

func TestDefaultOsctrldRateLimits(t *testing.T) {
	d := DefaultRateLimits()
	for name, tc := range map[string]struct {
		got    YAMLConfigurationRateLimit
		burst  int
		period time.Duration
	}{
		"osctrldAuth":     {d.OsctrldAuth, 10, time.Hour},
		"osctrld":         {d.Osctrld, 300, time.Minute},
		"osctrldDownload": {d.OsctrldDownload, 30, time.Minute},
	} {
		if tc.got.Burst != tc.burst || tc.got.Period != tc.period {
			t.Errorf("%s default = %d per %s, want %d per %s", name, tc.got.Burst, tc.got.Period, tc.burst, tc.period)
		}
	}
	if err := ValidateRateLimits(d, TLSRateLimits...); err != nil {
		t.Fatalf("default TLS rate limits should validate: %v", err)
	}
}

func TestValidateOsctrldRateLimits(t *testing.T) {
	for _, name := range []string{"osctrldAuth", "osctrld", "osctrldDownload"} {
		d := DefaultRateLimits()
		bad := YAMLConfigurationRateLimit{Burst: 5, Period: time.Hour, EvictAfter: time.Minute}
		switch name {
		case "osctrldAuth":
			d.OsctrldAuth = bad
		case "osctrld":
			d.Osctrld = bad
		case "osctrldDownload":
			d.OsctrldDownload = bad
		}
		err := ValidateRateLimits(d, TLSRateLimits...)
		if err == nil || !strings.Contains(err.Error(), name+" evictAfter") {
			t.Errorf("%s: expected evictAfter error, got %v", name, err)
		}
		if err := ValidateTLSConfigValues(TLSConfiguration{Service: YAMLConfigurationService{Auth: AuthNone}, RateLimits: &d}); err == nil {
			t.Errorf("%s: ValidateTLSConfigValues accepted an invalid limit", name)
		}
	}
}
