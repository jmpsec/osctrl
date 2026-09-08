package environments

import (
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"gorm.io/gorm"
)

// SetInactiveHours replaces the override atomically; nil restores inheritance.
func (environment *EnvManager) SetInactiveHours(envID uint, hours *int64) (before, after settings.InactivityPolicy, err error) {
	if envID == settings.NoEnvironmentID {
		return before, after, gorm.ErrRecordNotFound
	}
	if hours != nil {
		if err = settings.ValidateInactiveHours(*hours); err != nil {
			return
		}
	}
	err = environment.DB.Transaction(func(tx *gorm.DB) error {
		// An existing parent row serializes even the first override insertion.
		// A no-op write also takes the write lock on SQLite, unlike FOR UPDATE.
		lock := tx.Model(&TLSEnvironment{}).Where("id = ?", envID).UpdateColumn("id", gorm.Expr("id"))
		if lock.Error != nil {
			return lock.Error
		}
		var env TLSEnvironment
		if err := tx.First(&env, envID).Error; err != nil {
			return err
		}
		mgr := &settings.Settings{DB: tx}
		var readErr error
		before, readErr = mgr.InactivityPolicy(envID)
		if readErr != nil {
			return readErr
		}
		if err := tx.Unscoped().Where("service = ? AND name = ? AND environment_id = ?", config.ServiceAPI, settings.InactiveHours, envID).
			Delete(&settings.SettingValue{}).Error; err != nil {
			return err
		}
		if hours != nil {
			if err := mgr.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, *hours, envID); err != nil {
				return err
			}
		}
		after, readErr = mgr.InactivityPolicy(envID)
		return readErr
	})
	return
}
