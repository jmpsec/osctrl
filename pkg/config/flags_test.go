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
