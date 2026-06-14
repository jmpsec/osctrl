package config

import (
	"errors"
	"flag"
	"io"
	"strings"
	"time"
)

const (
	defaultTLSBaseURL    = "http://localhost:9000"
	defaultStateFile     = "fake_news_state.json"
	defaultOSQueryBinary = "osqueryi"
)

type Mode string

const (
	ModeSteady Mode = "steady"
	ModeSweep  Mode = "sweep"
)

type Config struct {
	TLSBaseURL      string
	APIBaseURL      string
	APIUsername     string
	APIPassword     string
	DiscoverEnvs    bool
	EnvUUID         string
	EnrollSecret    string
	OSQueryBinary   string
	StateFile       string
	Mode            Mode
	ErrorThreshold  float64
	P95Threshold    time.Duration
	SweepStartNodes int
	SweepStepNodes  int
	SweepStages     int
	SettleDuration  time.Duration
	SampleDuration  time.Duration

	Nodes           int
	StatusInterval  int
	ResultInterval  int
	ConfigInterval  int
	QueryInterval   int
	Verbose         bool
	Insecure        bool
	OutputMode      string
	SummaryInterval int
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.TLSBaseURL) == "" {
		return errors.New("tls base url is required")
	}
	if c.ShouldDiscoverEnvs() {
		if strings.TrimSpace(c.APIBaseURL) == "" {
			return errors.New("api base url is required when discover-envs is enabled")
		}
		if strings.TrimSpace(c.APIUsername) == "" {
			return errors.New("api username is required when discover-envs is enabled")
		}
		if strings.TrimSpace(c.APIPassword) == "" {
			return errors.New("api password is required when discover-envs is enabled")
		}
	} else {
		if strings.TrimSpace(c.EnvUUID) == "" {
			return errors.New("env uuid is required")
		}
		if strings.TrimSpace(c.EnrollSecret) == "" {
			return errors.New("enroll secret is required")
		}
	}

	switch c.normalizedMode() {
	case ModeSteady:
		return nil
	case ModeSweep:
		if c.ErrorThreshold <= 0 || c.P95Threshold <= 0 {
			return errors.New("sweep thresholds must be positive")
		}
		if c.SweepStartNodes <= 0 || c.SweepStepNodes <= 0 || c.SweepStages <= 0 {
			return errors.New("sweep sizing must be positive")
		}
		return nil
	default:
		return errors.New("mode must be steady or sweep")
	}
}

func Parse(args []string) (Config, error) {
	cfg := Config{}
	fs := flag.NewFlagSet("fake-news-go", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modeValue := string(ModeSteady)
	outputModeValue := "summary"

	fs.StringVar(&cfg.TLSBaseURL, "tls-url", defaultTLSBaseURL, "base url for osctrl-tls")
	fs.StringVar(&cfg.TLSBaseURL, "url", defaultTLSBaseURL, "base url for osctrl-tls")
	fs.StringVar(&cfg.TLSBaseURL, "u", defaultTLSBaseURL, "base url for osctrl-tls")
	fs.StringVar(&cfg.APIBaseURL, "api-url", "", "base url for osctrl-api")
	fs.StringVar(&cfg.APIUsername, "api-username", "", "username for osctrl-api login scenarios")
	fs.StringVar(&cfg.APIPassword, "api-password", "", "password for osctrl-api login scenarios")
	fs.BoolVar(&cfg.DiscoverEnvs, "discover-envs", false, "discover environment uuids and enroll secrets from osctrl-api before starting")
	fs.StringVar(&cfg.EnvUUID, "env", "", "environment uuid")
	fs.StringVar(&cfg.EnrollSecret, "secret", "", "enroll secret")
	fs.StringVar(&cfg.EnrollSecret, "s", "", "enroll secret")
	fs.StringVar(&cfg.OSQueryBinary, "osquery-binary", defaultOSQueryBinary, "osquery executable")
	fs.StringVar(&cfg.StateFile, "state", defaultStateFile, "path to persisted node state")
	fs.StringVar(&modeValue, "mode", string(ModeSteady), "steady or sweep")
	fs.Float64Var(&cfg.ErrorThreshold, "error-threshold", 0.02, "stop when error rate exceeds this ratio")
	fs.DurationVar(&cfg.P95Threshold, "p95-threshold", time.Second, "stop when p95 exceeds this duration")
	fs.IntVar(&cfg.SweepStartNodes, "sweep-start-nodes", 25, "starting node count for sweep mode")
	fs.IntVar(&cfg.SweepStepNodes, "sweep-step-nodes", 25, "increment between sweep stages")
	fs.IntVar(&cfg.SweepStages, "sweep-stages", 8, "maximum number of sweep stages")
	fs.DurationVar(&cfg.SettleDuration, "settle", 10*time.Second, "settle duration before sampling a sweep stage")
	fs.DurationVar(&cfg.SampleDuration, "sample", 20*time.Second, "sampling duration for a sweep stage")

	fs.IntVar(&cfg.Nodes, "nodes", 5, "number of random nodes to simulate")
	fs.IntVar(&cfg.Nodes, "n", 5, "number of random nodes to simulate")
	fs.IntVar(&cfg.StatusInterval, "status", 60, "interval in seconds for status requests")
	fs.IntVar(&cfg.StatusInterval, "S", 60, "interval in seconds for status requests")
	fs.IntVar(&cfg.ResultInterval, "result", 60, "interval in seconds for result requests")
	fs.IntVar(&cfg.ResultInterval, "R", 60, "interval in seconds for result requests")
	fs.IntVar(&cfg.ConfigInterval, "config", 45, "interval in seconds for config requests")
	fs.IntVar(&cfg.ConfigInterval, "c", 45, "interval in seconds for config requests")
	fs.IntVar(&cfg.QueryInterval, "query", 30, "interval in seconds for query requests")
	fs.IntVar(&cfg.QueryInterval, "q", 30, "interval in seconds for query requests")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "skip TLS certificate verification")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "enable verbose output")
	fs.BoolVar(&cfg.Verbose, "v", false, "enable verbose output")
	fs.StringVar(&outputModeValue, "output-mode", "summary", "output mode: quiet, summary, verbose, dashboard, json")
	fs.StringVar(&outputModeValue, "mode-output", "summary", "output mode: quiet, summary, verbose, dashboard, json")
	fs.StringVar(&outputModeValue, "display-mode", "summary", "output mode: quiet, summary, verbose, dashboard, json")
	fs.IntVar(&cfg.SummaryInterval, "summary-interval", 30, "interval in seconds for summary reports")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.TLSBaseURL = strings.TrimSpace(cfg.TLSBaseURL)
	cfg.APIBaseURL = strings.TrimSpace(cfg.APIBaseURL)
	cfg.APIUsername = strings.TrimSpace(cfg.APIUsername)
	cfg.APIPassword = strings.TrimSpace(cfg.APIPassword)
	cfg.EnvUUID = strings.TrimSpace(cfg.EnvUUID)
	cfg.EnrollSecret = strings.TrimSpace(cfg.EnrollSecret)
	cfg.OSQueryBinary = strings.TrimSpace(cfg.OSQueryBinary)
	cfg.StateFile = strings.TrimSpace(cfg.StateFile)
	cfg.Mode, cfg.OutputMode = normalizeModes(modeValue, outputModeValue)

	return cfg, cfg.Validate()
}

func (c Config) normalizedMode() Mode {
	if strings.TrimSpace(string(c.Mode)) == "" {
		return ModeSteady
	}
	return Mode(strings.ToLower(strings.TrimSpace(string(c.Mode))))
}

func normalizeModes(modeValue, outputModeValue string) (Mode, string) {
	modeValue = strings.ToLower(strings.TrimSpace(modeValue))
	outputModeValue = strings.ToLower(strings.TrimSpace(outputModeValue))
	if outputModeValue == "" {
		outputModeValue = "summary"
	}

	if isOutputMode(modeValue) {
		return ModeSteady, modeValue
	}

	if modeValue == "" {
		modeValue = string(ModeSteady)
	}

	return Mode(modeValue), outputModeValue
}

func isOutputMode(value string) bool {
	switch value {
	case "quiet", "summary", "verbose", "dashboard", "json":
		return true
	default:
		return false
	}
}

func (c Config) ShouldDiscoverEnvs() bool {
	return c.DiscoverEnvs
}
