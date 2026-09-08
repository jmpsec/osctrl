package environments

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestInactiveHoursConcurrentWritesAndReset(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "settings.db")+"?_busy_timeout=10000"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&TLSEnvironment{}, &settings.SettingValue{}))
	env := TLSEnvironment{Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	mgr := &EnvManager{DB: db}
	conf := &settings.Settings{DB: db}
	require.NoError(t, conf.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 168, 0))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hours := int64(i + 1)
			_, after, err := mgr.SetInactiveHours(env.ID, &hours)
			if err == nil && after.InactiveHours != hours {
				err = fmt.Errorf("readback %d, want %d", after.InactiveHours, hours)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var count int64
	require.NoError(t, db.Model(&settings.SettingValue{}).Where("environment_id = ?", env.ID).Count(&count).Error)
	require.Equal(t, int64(1), count)
	before, after, err := mgr.SetInactiveHours(env.ID, nil)
	require.NoError(t, err)
	require.Equal(t, "environment", before.Source)
	require.Equal(t, "global", after.Source)
	require.Equal(t, int64(168), after.InactiveHours)
	require.Nil(t, after.OverrideHours)
	_, _, err = mgr.SetInactiveHours(env.ID, nil)
	require.NoError(t, err, "reset is idempotent")
	hours := int64(2)
	_, _, err = mgr.SetInactiveHours(0, &hours)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	_, _, err = mgr.SetInactiveHours(env.ID+1, &hours)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	require.Equal(t, int64(168), conf.InactiveHours(0))
	_, _, err = mgr.SetInactiveHours(env.ID, &hours)
	require.NoError(t, err)
	require.NoError(t, mgr.Delete(env.Name))
	require.NoError(t, db.Unscoped().Model(&settings.SettingValue{}).Where("environment_id = ?", env.ID).Count(&count).Error)
	require.Zero(t, count)
	require.Equal(t, int64(168), conf.InactiveHours(0))
}
