package settings

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestRedisSettingsCacheReturnsCachedMapAfterDatabaseChanges(t *testing.T) {
	db := setupSettingsTestDB(t)
	conf := &Settings{DB: db}
	require.NoError(t, conf.NewIntegerValue(config.ServiceTLS, AcceleratedSeconds, 60, NoEnvironmentID))

	client, _ := newSettingsRedisTestClient(t)
	cache := NewRedisSettingsCache(conf, client, config.ServiceTLS, NoEnvironmentID, time.Minute)

	ctx := context.Background()
	first, err := cache.GetMap(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(60), first[AcceleratedSeconds].Integer)

	require.NoError(t, conf.SetInteger(10, config.ServiceTLS, AcceleratedSeconds, NoEnvironmentID))

	second, err := cache.GetMap(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(60), second[AcceleratedSeconds].Integer)
}

func TestRedisSettingsCacheRefreshesAfterInvalidation(t *testing.T) {
	db := setupSettingsTestDB(t)
	conf := &Settings{DB: db}
	require.NoError(t, conf.NewIntegerValue(config.ServiceTLS, AcceleratedSeconds, 60, NoEnvironmentID))

	client, _ := newSettingsRedisTestClient(t)
	cache := NewRedisSettingsCache(conf, client, config.ServiceTLS, NoEnvironmentID, time.Minute)

	ctx := context.Background()
	_, err := cache.GetMap(ctx)
	require.NoError(t, err)
	require.NoError(t, conf.SetInteger(10, config.ServiceTLS, AcceleratedSeconds, NoEnvironmentID))
	require.NoError(t, cache.Invalidate(ctx))

	got, err := cache.GetMap(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(10), got[AcceleratedSeconds].Integer)
}
