package config

import (
	"strings"
	"testing"
	"time"
)

const validEnvUUID = "123e4567-e89b-12d3-a456-426614174000"

func TestValidateRequiresTLSInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "missing tls base url",
			cfg: Config{
				EnvUUID:      validEnvUUID,
				EnrollSecret: "secret",
			},
			wantErr: "tls base url is required",
		},
		{
			name: "missing env uuid",
			cfg: Config{
				TLSBaseURL:   "http://localhost:9000",
				EnrollSecret: "secret",
			},
			wantErr: "env uuid is required",
		},
		{
			name: "missing enroll secret",
			cfg: Config{
				TLSBaseURL: "http://localhost:9000",
				EnvUUID:    validEnvUUID,
			},
			wantErr: "enroll secret is required",
		},
		{
			name: "discover mode missing api base url",
			cfg: Config{
				TLSBaseURL:   "http://localhost:9000",
				DiscoverEnvs: true,
				APIUsername:  "admin",
				APIPassword:  "secret",
			},
			wantErr: "api base url is required when discover-envs is enabled",
		},
		{
			name: "discover mode missing api username",
			cfg: Config{
				TLSBaseURL:   "http://localhost:9000",
				DiscoverEnvs: true,
				APIBaseURL:   "http://localhost:9002",
				APIPassword:  "secret",
			},
			wantErr: "api username is required when discover-envs is enabled",
		},
		{
			name: "discover mode missing api password",
			cfg: Config{
				TLSBaseURL:   "http://localhost:9000",
				DiscoverEnvs: true,
				APIBaseURL:   "http://localhost:9002",
				APIUsername:  "admin",
			},
			wantErr: "api password is required when discover-envs is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateSweepThresholdDefaults(t *testing.T) {
	t.Parallel()

	cfg := validSweepConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid sweep config, got %v", err)
	}
}

func TestValidateRejectsNonPositiveSweepThresholds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "error threshold",
			mut: func(cfg *Config) {
				cfg.ErrorThreshold = 0
			},
		},
		{
			name: "p95 threshold",
			mut: func(cfg *Config) {
				cfg.P95Threshold = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validSweepConfig()
			tt.mut(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected sweep threshold validation error")
			}
			if !strings.Contains(err.Error(), "sweep thresholds must be positive") {
				t.Fatalf("expected threshold validation error, got %v", err)
			}
		})
	}
}

func TestValidateRejectsNonPositiveSweepSizing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "start nodes",
			mut: func(cfg *Config) {
				cfg.SweepStartNodes = 0
			},
		},
		{
			name: "step nodes",
			mut: func(cfg *Config) {
				cfg.SweepStepNodes = 0
			},
		},
		{
			name: "stages",
			mut: func(cfg *Config) {
				cfg.SweepStages = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validSweepConfig()
			tt.mut(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected sweep sizing validation error")
			}
			if !strings.Contains(err.Error(), "sweep sizing must be positive") {
				t.Fatalf("expected sizing validation error, got %v", err)
			}
		})
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{"-env", validEnvUUID, "-secret", "secret"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if cfg.TLSBaseURL != "http://localhost:9000" {
		t.Fatalf("expected default tls base url, got %q", cfg.TLSBaseURL)
	}
	if cfg.Mode != ModeSteady {
		t.Fatalf("expected steady mode default, got %q", cfg.Mode)
	}
	if cfg.OSQueryBinary != "osqueryi" {
		t.Fatalf("expected osquery binary default, got %q", cfg.OSQueryBinary)
	}
	if cfg.StateFile != "fake_news_state.json" {
		t.Fatalf("expected state file default, got %q", cfg.StateFile)
	}
	if cfg.ErrorThreshold != 0.02 {
		t.Fatalf("expected error threshold default 0.02, got %v", cfg.ErrorThreshold)
	}
	if cfg.P95Threshold != time.Second {
		t.Fatalf("expected p95 threshold default 1s, got %v", cfg.P95Threshold)
	}
	if cfg.SweepStartNodes != 25 || cfg.SweepStepNodes != 25 || cfg.SweepStages != 8 {
		t.Fatalf("unexpected sweep defaults: start=%d step=%d stages=%d", cfg.SweepStartNodes, cfg.SweepStepNodes, cfg.SweepStages)
	}
	if cfg.SettleDuration != 10*time.Second || cfg.SampleDuration != 20*time.Second {
		t.Fatalf("unexpected sweep timing defaults: settle=%v sample=%v", cfg.SettleDuration, cfg.SampleDuration)
	}
	if cfg.Nodes != 5 {
		t.Fatalf("expected nodes default 5, got %d", cfg.Nodes)
	}
	if cfg.StatusInterval != 60 || cfg.ResultInterval != 60 || cfg.ConfigInterval != 45 || cfg.QueryInterval != 30 {
		t.Fatalf(
			"unexpected interval defaults: status=%d result=%d config=%d query=%d",
			cfg.StatusInterval,
			cfg.ResultInterval,
			cfg.ConfigInterval,
			cfg.QueryInterval,
		)
	}
	if cfg.OutputMode != "summary" {
		t.Fatalf("expected output mode default summary, got %q", cfg.OutputMode)
	}
	if cfg.SummaryInterval != 30 {
		t.Fatalf("expected summary interval default 30, got %d", cfg.SummaryInterval)
	}
}

func TestParseAcceptsDiscoverModeWithoutManualEnvSecret(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"-discover-envs",
		"-api-url", "http://localhost:9002",
		"-api-username", "admin",
		"-api-password", "secret",
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !cfg.DiscoverEnvs {
		t.Fatal("expected discover-envs to be enabled")
	}
	if cfg.EnvUUID != "" {
		t.Fatalf("expected empty env uuid in discover mode, got %q", cfg.EnvUUID)
	}
	if cfg.EnrollSecret != "" {
		t.Fatalf("expected empty enroll secret in discover mode, got %q", cfg.EnrollSecret)
	}
}

func TestParseAcceptsLegacyURLAlias(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"-url", "https://tls.example.test",
		"-env", validEnvUUID,
		"-secret", "secret",
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if cfg.TLSBaseURL != "https://tls.example.test" {
		t.Fatalf("expected legacy url alias to populate tls base url, got %q", cfg.TLSBaseURL)
	}
}

func validSweepConfig() Config {
	return Config{
		TLSBaseURL:      "http://localhost:9000",
		EnvUUID:         validEnvUUID,
		EnrollSecret:    "secret",
		Mode:            ModeSweep,
		ErrorThreshold:  0.02,
		P95Threshold:    time.Second,
		SweepStartNodes: 10,
		SweepStepNodes:  10,
		SweepStages:     5,
	}
}
