package config

import (
	"testing"
	"time"

	"github.com/urfave/cli/v3"
)

func TestServicePostureEnabledFlagDefaultsOff(t *testing.T) {
	params := &ServiceParameters{Service: &YAMLConfigurationService{}}
	flags := initServiceFlags(params)

	if params.Service.PostureEnabled {
		t.Fatalf("posture enabled default: got true want false")
	}

	var postureFlag *cli.BoolFlag
	for _, flag := range flags {
		if f, ok := flag.(*cli.BoolFlag); ok && f.Name == "posture-enabled" {
			postureFlag = f
			break
		}
	}
	if postureFlag == nil {
		t.Fatalf("missing posture-enabled service flag")
	}
	if postureFlag.Value {
		t.Fatalf("posture-enabled flag default: got true want false")
	}
	if postureFlag.Destination != &params.Service.PostureEnabled {
		t.Fatalf("posture-enabled flag destination does not wire Service.PostureEnabled")
	}
}

func TestOsqueryAcceleratedFlagDefaultsOff(t *testing.T) {
	params := &ServiceParameters{Osquery: &YAMLConfigurationOsquery{}}
	flags := initOsqueryFlags(params)

	if params.Osquery.Accelerated {
		t.Fatalf("accelerated osquery default: got true want false")
	}

	var acceleratedFlag *cli.BoolFlag
	for _, flag := range flags {
		if f, ok := flag.(*cli.BoolFlag); ok && f.Name == "osquery-accelerated" {
			acceleratedFlag = f
			break
		}
	}
	if acceleratedFlag == nil {
		t.Fatalf("missing osquery-accelerated flag")
	}
	if acceleratedFlag.Value {
		t.Fatalf("osquery-accelerated flag default: got true want false")
	}
	if acceleratedFlag.Destination != &params.Osquery.Accelerated {
		t.Fatalf("osquery-accelerated flag destination does not wire Osquery.Accelerated")
	}
}

func TestOsqueryFileExplorerFlagDefaultsOff(t *testing.T) {
	params := &ServiceParameters{Osquery: &YAMLConfigurationOsquery{}}
	flags := initOsqueryFlags(params)

	if params.Osquery.FileExplorer {
		t.Fatalf("file explorer osquery default: got true want false")
	}

	var fileExplorerFlag *cli.BoolFlag
	for _, flag := range flags {
		if f, ok := flag.(*cli.BoolFlag); ok && f.Name == "osquery-file-explorer" {
			fileExplorerFlag = f
			break
		}
	}
	if fileExplorerFlag == nil {
		t.Fatalf("missing osquery-file-explorer flag")
	}
	if fileExplorerFlag.Value {
		t.Fatalf("osquery-file-explorer flag default: got true want false")
	}
	if fileExplorerFlag.Destination != &params.Osquery.FileExplorer {
		t.Fatalf("osquery-file-explorer flag destination does not wire Osquery.FileExplorer")
	}
}

func TestRateLimitFlagsWireDefaults(t *testing.T) {
	params := &ServiceParameters{}
	flags := initRateLimitFlags(params, ServiceAPI)

	if params.RateLimits == nil {
		t.Fatal("rate limits were not initialized")
	}
	if params.RateLimits.Login.Burst != 10 {
		t.Fatalf("login burst default: got %d want 10", params.RateLimits.Login.Burst)
	}
	if params.RateLimits.ServiceConfigApply.Period != 10*time.Minute {
		t.Fatalf("service-config apply period default: got %s want 10m", params.RateLimits.ServiceConfigApply.Period)
	}

	var loginBurst *cli.IntFlag
	for _, flag := range flags {
		if f, ok := flag.(*cli.IntFlag); ok && f.Name == "rate-limit-login-burst" {
			loginBurst = f
			break
		}
	}
	if loginBurst == nil {
		t.Fatal("missing login burst rate-limit flag")
	}
	if loginBurst.Destination != &params.RateLimits.Login.Burst {
		t.Fatal("login burst flag destination does not wire RateLimits.Login.Burst")
	}
}
