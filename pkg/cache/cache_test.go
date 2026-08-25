package cache

import (
	"errors"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
)

func TestRedisConnectionErrorExplainsPasswordWithoutServerAuth(t *testing.T) {
	baseErr := errors.New("ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?")

	err := redisConnectionError(config.YAMLConfigurationRedis{Password: "secret"}, baseErr)
	if !errors.Is(err, baseErr) {
		t.Fatal("wrapped error does not preserve original Redis error")
	}
	if !strings.Contains(err.Error(), "redis.password is set") {
		t.Fatalf("error = %q, want redis.password hint", err)
	}
}

func TestRedisConnectionErrorExplainsConnectionStringCredentialsWithoutServerAuth(t *testing.T) {
	baseErr := errors.New("ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?")

	err := redisConnectionError(config.YAMLConfigurationRedis{ConnectionString: "redis://:secret@127.0.0.1:6379/0"}, baseErr)
	if !errors.Is(err, baseErr) {
		t.Fatal("wrapped error does not preserve original Redis error")
	}
	if !strings.Contains(err.Error(), "redis.connectionString includes credentials") {
		t.Fatalf("error = %q, want redis.connectionString hint", err)
	}
}

func TestRedisConnectionErrorLeavesOtherErrorsAlone(t *testing.T) {
	baseErr := errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")

	err := redisConnectionError(config.YAMLConfigurationRedis{}, baseErr)
	if err != baseErr {
		t.Fatalf("error = %v, want original error", err)
	}
}
