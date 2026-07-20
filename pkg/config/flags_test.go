package config

import (
	"testing"

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
