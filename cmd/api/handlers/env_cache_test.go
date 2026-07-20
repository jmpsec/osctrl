package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
)

func TestWithEnvCacheWiresEnvironmentCache(t *testing.T) {
	envCache := &environments.EnvCache{}

	h := CreateHandlersApi(WithEnvCache(envCache))

	if h.EnvCache != envCache {
		t.Fatalf("EnvCache was not wired")
	}
}
