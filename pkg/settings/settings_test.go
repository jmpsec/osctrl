package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
)

func setupSettingsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// Use a unique DSN per test so in-memory databases don't bleed into
	// each other (file::memory:?cache=shared is a single shared DB).
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")
	require.NoError(t, db.AutoMigrate(&SettingValue{}), "Failed to migrate schema")
	return db
}

// InactiveHours must return DefaultInactiveHours when the setting row is
// missing from the DB. This is the regression for the bug where the API
// service (which does not seed inactive_hours) would get 0 hours, causing
// every node to appear inactive on the dashboard.
func TestInactiveHours_DefaultsWhenMissing(t *testing.T) {
	db := setupSettingsTestDB(t)
	conf := &Settings{DB: db}

	got := conf.InactiveHours(NoEnvironmentID)
	assert.Equal(t, DefaultInactiveHours, got,
		"InactiveHours should fall back to DefaultInactiveHours when setting is absent")
}

// InactiveHours must return DefaultInactiveHours when the stored value is 0
// or negative, since a zero threshold makes every node inactive.
func TestInactiveHours_DefaultsOnNonPositive(t *testing.T) {
	tests := []struct {
		name  string
		value int64
	}{
		{"zero value", 0},
		{"negative value", -5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupSettingsTestDB(t)
			conf := &Settings{DB: db}
			require.NoError(t, conf.NewIntegerValue(config.ServiceAdmin, InactiveHours, tt.value, NoEnvironmentID))
			got := conf.InactiveHours(NoEnvironmentID)
			assert.Equal(t, DefaultInactiveHours, got,
				"InactiveHours should fall back to DefaultInactiveHours for non-positive stored value")
		})
	}
}

// InactiveHours must return the configured value when it is positive.
func TestInactiveHours_ReturnsConfigured(t *testing.T) {
	db := setupSettingsTestDB(t)
	conf := &Settings{DB: db}
	const configured = int64(168)
	require.NoError(t, conf.NewIntegerValue(config.ServiceAdmin, InactiveHours, configured, NoEnvironmentID))
	got := conf.InactiveHours(NoEnvironmentID)
	assert.Equal(t, configured, got,
		"InactiveHours should return the stored positive value")
}
