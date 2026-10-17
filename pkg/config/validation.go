package config

import (
	"fmt"
	"time"
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
	LoggingKafka:    true,
	LoggingElastic:  true,
	LoggingHTTP:     true,
}

// ValidateCarverType checks the carver type is one osctrl can run with.
// "local" was accepted for years but never implemented: blocks were never
// written to carvesDir, so it is rejected instead of failing every carve.
func ValidateCarverType(carverType string) error {
	switch carverType {
	case CarverDB, CarverS3:
		return nil
	case CarverLocal:
		return fmt.Errorf("carver type %q is not supported; use %q (blocks stored in the database) or %q", CarverLocal, CarverDB, CarverS3)
	}
	return fmt.Errorf("invalid carver method: %s", carverType)
}

const maxRateLimitBurst = 100000

// DefaultRateLimits returns the existing hardcoded HTTP rate-limit defaults.
func DefaultRateLimits() YAMLConfigurationRateLimits {
	return YAMLConfigurationRateLimits{
		Login: YAMLConfigurationRateLimit{
			Burst:      10,
			Period:     time.Minute,
			EvictAfter: 10 * time.Minute,
			RetryAfter: 60,
		},
		PreAuth: YAMLConfigurationRateLimit{
			Burst:      60,
			Period:     time.Minute,
			EvictAfter: 10 * time.Minute,
			RetryAfter: 60,
		},
		ServiceConfigApply: YAMLConfigurationRateLimit{
			Burst:      3,
			Period:     10 * time.Minute,
			EvictAfter: 30 * time.Minute,
			RetryAfter: 60,
		},
		Enroll: YAMLConfigurationRateLimit{
			Burst:      20,
			Period:     time.Minute,
			EvictAfter: 10 * time.Minute,
			RetryAfter: 60,
		},
	}
}

// DefaultRateLimitsPtr returns DefaultRateLimits as a pointer for optional
// config sections.
func DefaultRateLimitsPtr() *YAMLConfigurationRateLimits {
	defaults := DefaultRateLimits()
	return &defaults
}

// ValidateRateLimits validates named rate-limit entries.
func ValidateRateLimits(cfg YAMLConfigurationRateLimits, names ...string) error {
	limits := map[string]YAMLConfigurationRateLimit{
		"login":              cfg.Login,
		"preAuth":            cfg.PreAuth,
		"serviceConfigApply": cfg.ServiceConfigApply,
		"enroll":             cfg.Enroll,
	}
	for _, name := range names {
		limit, ok := limits[name]
		if !ok {
			return fmt.Errorf("unknown rate limit %q", name)
		}
		if err := validateRateLimit(name, limit); err != nil {
			return err
		}
	}
	return nil
}

func validateRateLimit(name string, limit YAMLConfigurationRateLimit) error {
	if limit.Burst <= 0 {
		return fmt.Errorf("%s burst must be greater than 0", name)
	}
	if limit.Burst > maxRateLimitBurst {
		return fmt.Errorf("%s burst must be <= %d", name, maxRateLimitBurst)
	}
	if limit.Period <= 0 {
		return fmt.Errorf("%s period must be greater than 0", name)
	}
	if limit.EvictAfter < limit.Period {
		return fmt.Errorf("%s evictAfter must be greater than or equal to period", name)
	}
	if limit.RetryAfter < 0 {
		return fmt.Errorf("%s retryAfter must be >= 0", name)
	}
	if limit.MaxBuckets < 0 {
		return fmt.Errorf("%s maxBuckets must be >= 0", name)
	}
	return nil
}

// Helper to validate the TLS configuration values
func ValidateTLSConfigValues(cfg TLSConfiguration) error {
	// Check if values are valid
	if !validAuth[cfg.Service.Auth] {
		return fmt.Errorf("invalid auth method: %s", cfg.Service.Auth)
	}
	if cfg.Logger != nil {
		if len(cfg.Logger.Types) > 0 {
			for _, loggingType := range LoggerTypes(cfg.Logger) {
				if !validLogging[loggingType] {
					return fmt.Errorf("invalid logging method: %s", loggingType)
				}
			}
		} else if !validLogging[cfg.Logger.Type] {
			return fmt.Errorf("invalid logging method: %s", cfg.Logger.Type)
		}
	}
	if cfg.Carver != nil {
		if err := ValidateCarverType(cfg.Carver.Type); err != nil {
			return err
		}
	}
	if cfg.RateLimits != nil {
		if err := ValidateRateLimits(*cfg.RateLimits, "enroll"); err != nil {
			return err
		}
	}
	// No errors!
	return nil
}
