package settings

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/rs/zerolog/log"
)

// Types of settings values
const (
	TypeString  string = "string"
	TypeBoolean string = "boolean"
	TypeInteger string = "integer"
)

// Types of script
const (
	ScriptEnroll string = "enroll"
	ScriptRemove string = "remove"
)

// Types of enroll/remove actions
const (
	ActionExpire    string = "expire"
	ActionExtend    string = "extend"
	ActionRotate    string = "rotate"
	ActionNotexpire string = "notexpire"
	SetMacPackage   string = "set_pkg"
	SetMsiPackage   string = "set_msi"
	SetDebPackage   string = "set_deb"
	SetRpmPackage   string = "set_rpm"
)

// Types of query/carve actions
const (
	QueryDelete   string = "delete"
	QueryExpire   string = "expire"
	QueryComplete string = "complete"
	CarveDelete   string = QueryDelete
	CarveExpire   string = QueryExpire
	CarveComplete string = QueryComplete
)

// Types of package
const (
	PackageDeb string = "deb"
	PackageRpm string = "rpm"
	PackagePkg string = "pkg"
	PackageMsi string = "msi"
)

// Types of download target
const (
	DownloadSecret       string = "secret"
	DownloadCert         string = "cert"
	DownloadFlags        string = "flags"
	DownloadFlagsMac     string = "flagsMac"
	DownloadFlagsWin     string = "flagsWindows"
	DownloadFlagsLinux   string = "flagsLinux"
	DownloadFlagsFreeBSD string = "flagsFreeBSD"
)

// Types of platform
const (
	PlatformDarwin  string = "darwin"
	PlatformLinux   string = "linux"
	PlatformWindows string = "windows"
)

// Names for all possible settings values for services
const (
	RefreshSettings    string = "refresh_settings"
	ServiceMetrics     string = "service_metrics"
	InactiveHours      string = "inactive_hours"
	AcceleratedSeconds string = "accelerated_seconds"
	OnelinerExpiration string = "oneliner_expiration"
	// AlertHistoryRetentionDays bounds how long dispatched-alert rows
	// stay in alert_history before the periodic prune deletes them.
	AlertHistoryRetentionDays string = "alert_history_retention_days"
)

// Values for generic IDs
const (
	NoEnvironmentID = iota
)

// DefaultInactiveHours is the fallback threshold (in hours) for classifying
// nodes as active vs inactive when the inactive_hours setting is absent or
// invalid. Keeps every service — including the API, which does not seed the
// setting itself — from treating all nodes as inactive when the DB row is
// missing.
const DefaultInactiveHours int64 = 72

// DefaultAlertHistoryRetentionDays is the fallback retention (in days) for
// alert_history rows when the alert_history_retention_days setting is absent
// or invalid. 30 days balances audit trail depth against table growth; 0
// (disable pruning) is rejected so the table can never grow unbounded by
// accident.
const DefaultAlertHistoryRetentionDays int64 = 30

// SettingValue to hold each value for settings
type SettingValue struct {
	gorm.Model
	Name          string `gorm:"index"`
	Service       string
	EnvironmentID uint
	Type          string
	String        string
	Boolean       bool
	Integer       int64
	Info          string
}

// MapSettings to hold all values by service
type MapSettings map[string]SettingValue

// Settings keeps all settings values
type Settings struct {
	DB *gorm.DB
}

// ValidServices to check validity of settings service
var ValidServices = map[string]struct{}{
	config.ServiceTLS: {},
	config.ServiceAPI: {},
}

// NewSettings to initialize the access to settings and table
func NewSettings(backend *gorm.DB) *Settings {
	s := &Settings{DB: backend}
	// table setting_values
	if err := backend.AutoMigrate(&SettingValue{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (setting_values): %v", err)
	}
	return s
}

// EmptyValue creates an empty value
func (conf *Settings) EmptyValue(service, name, typeValue string, envID uint) SettingValue {
	return SettingValue{
		Name:          name,
		Service:       service,
		EnvironmentID: envID,
		Type:          typeValue,
		String:        "",
		Integer:       int64(0),
		Boolean:       false,
		Info:          "",
	}
}

// NewValue creates a new settings value
func (conf *Settings) NewValue(service, name, typeValue string, value interface{}, envID uint) error {
	// Empty new value
	entry := conf.EmptyValue(service, name, typeValue, envID)
	switch typeValue {
	case TypeBoolean:
		entry.Boolean = value.(bool)
	case TypeInteger:
		entry.Integer = value.(int64)
	case TypeString:
		entry.String = value.(string)
	}
	// Create record in database
	if err := conf.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("create NewValue %w", err)
	}
	return nil
}

// NewStringValue creates a new settings value
func (conf *Settings) NewStringValue(service, name, value string, envID uint) error {
	return conf.NewValue(service, name, TypeString, value, envID)
}

// NewBooleanValue creates a new settings value
func (conf *Settings) NewBooleanValue(service, name string, value bool, envID uint) error {
	return conf.NewValue(service, name, TypeBoolean, value, envID)
}

// NewIntegerValue creates a new settings value
func (conf *Settings) NewIntegerValue(service, name string, value int64, envID uint) error {
	return conf.NewValue(service, name, TypeInteger, value, envID)
}

// VerifyService to make sure service is valid
func (conf *Settings) VerifyService(sType string) bool {
	_, ok := ValidServices[sType]
	return ok
}

// DeleteValue deletes an existing settings value
func (conf *Settings) DeleteValue(service, name string, envID uint) error {
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("deleteValue %w", err)
	}
	if err := conf.DB.Unscoped().Delete(&value).Error; err != nil {
		return fmt.Errorf("delete %w", err)
	}
	return nil
}

// RetrieveAllValues retrieves and returns all values from backend
func (conf *Settings) RetrieveAllValues() ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValues retrieves and returns all values from backend
func (conf *Settings) RetrieveValues(service string, envID uint) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("service = ? AND environment_id = ?", service, envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValue retrieves one value from settings by service and name from backend
func (conf *Settings) RetrieveValue(service, name string, envID uint) (SettingValue, error) {
	var value SettingValue
	if err := conf.DB.Where("service = ? AND environment_id = ?", service, envID).Where("name = ?", name).First(&value).Error; err != nil {
		return SettingValue{}, err
	}
	return value, nil
}

// GetMap returns the map of values by service
func (conf *Settings) GetMap(service string, envID uint) (MapSettings, error) {
	all, err := conf.RetrieveValues(service, envID)
	if err != nil {
		return MapSettings{}, fmt.Errorf("error getting values %w", err)
	}
	_map := make(MapSettings)
	for _, c := range all {
		_map[c.Name] = c
	}
	return _map, nil
}

// SetInteger sets a numeric settings value by service and name
func (conf *Settings) SetInteger(intValue int64, service, name string, envID uint) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("setInteger %d %w", intValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update(TypeInteger, intValue).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	log.Debug().Msgf("SetInteger %d %s %s", intValue, service, name)
	return nil
}

// GetInteger gets a numeric settings value by service and name
func (conf *Settings) GetInteger(service, name string, envID uint) (int64, error) {
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return 0, err
	}
	return value.Integer, nil
}

// SetBoolean sets a boolean settings value by service and name
func (conf *Settings) SetBoolean(boolValue bool, service, name string, envID uint) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("setBoolean %v %w", boolValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Updates(map[string]interface{}{TypeBoolean: boolValue}).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	log.Debug().Msgf("SetBoolean %v %s %s", boolValue, service, name)
	return nil
}

// SetString sets a boolean settings value by service and name
func (conf *Settings) SetString(strValue string, service, name string, envID uint) error {
	val, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("setString %s %w", strValue, err)
	}
	// Update
	if err := conf.DB.Model(&val).Update(TypeString, strValue).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	log.Debug().Msgf("SetString %s %s %s", strValue, service, name)
	return nil
}

// SetInfo sets the info of a setting
func (conf *Settings) SetInfo(info string, service, name string, envID uint) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("setInfo %s %w", info, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update("info", info).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	log.Debug().Msgf("SetInfo %s %s %s", info, service, name)
	return nil
}

// IsValue checks if a settings value exists by service and name
func (conf *Settings) IsValue(service, name string, envID uint) bool {
	_, err := conf.RetrieveValue(service, name, envID)
	return err == nil
}

// RefreshSettings gets the interval in seconds to refresh settings by service
func (conf *Settings) RefreshSettings(service string) int64 {
	value, err := conf.RetrieveValue(service, RefreshSettings, NoEnvironmentID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// InactiveHours gets the value in hours for a node to be inactive by service.
// Returns DefaultInactiveHours when the setting is absent or invalid so that
// callers never receive a zero threshold (which would make every node appear
// inactive).
func (conf *Settings) InactiveHours(envID uint) int64 {
	value, err := conf.RetrieveValue(config.ServiceAPI, InactiveHours, envID)
	if err != nil {
		return DefaultInactiveHours
	}
	if value.Integer <= 0 {
		return DefaultInactiveHours
	}
	return value.Integer
}

// OnelinerExpiration checks if enrolling links will expire
func (conf *Settings) OnelinerExpiration(envID uint) bool {
	value, err := conf.RetrieveValue(config.ServiceTLS, OnelinerExpiration, envID)
	if err != nil {
		return false
	}
	return value.Boolean
}

// AlertHistoryRetentionDays gets how long dispatched-alert rows are kept
// before pruning. Returns DefaultAlertHistoryRetentionDays when the setting
// is absent, invalid, or zero (a zero would disable pruning and let the
// table grow unbounded, so it is treated as "use the default").
func (conf *Settings) AlertHistoryRetentionDays() int64 {
	value, err := conf.RetrieveValue(config.ServiceTLS, AlertHistoryRetentionDays, NoEnvironmentID)
	if err != nil {
		return DefaultAlertHistoryRetentionDays
	}
	if value.Integer <= 0 {
		return DefaultAlertHistoryRetentionDays
	}
	return value.Integer
}
