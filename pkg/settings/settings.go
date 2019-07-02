package settings

import (
	"fmt"
	"log"

	"github.com/jinzhu/gorm"
)

// Types of services
const (
	ServiceTLS   string = "tls"
	ServiceAdmin string = "admin"
)

// Types of settings values
const (
	TypeString  string = "string"
	TypeBoolean string = "boolean"
	TypeInteger string = "integer"
)

// Types of authentication
const (
	AuthNone    string = "none"
	AuthJSON    string = "json"
	AuthDB      string = "db"
	AuthSAML    string = "saml"
	AuthHeaders string = "headers"
)

// Types of logging
const (
	LoggingNone    string = "none"
	LoggingStdout  string = "stdout"
	LoggingDB      string = "db"
	LoggingGraylog string = "graylog"
	LoggingSplunk  string = "splunk"
	LoggingELK     string = "elk"
)

// Names for settings values
const (
	DebugHTTP       string = "debug_http"
	DebugService    string = "debug_service"
	RefreshEnvs     string = "refresh_envs"
	RefreshSettings string = "refresh_settings"
	CleanupSessions string = "cleanup_sessions"
	ServiceMetrics  string = "service_metrics"
	MetricsHost     string = "metrics_host"
	MetricsPort     string = "metrics_port"
	MetricsProtocol string = "metrics_protocol"
	DefaultEnv      string = "default_env"
)

// SettingValue to hold each value for settings
type SettingValue struct {
	gorm.Model
	Name    string `gorm:"index"`
	Service string
	Type    string
	String  string
	Boolean bool
	Integer int64
	Info    string
}

// MapSettings to hold all values by service
type MapSettings map[string]SettingValue

// Settings keeps all settings values
type Settings struct {
	DB *gorm.DB
}

// NewSettings to initialize the access to settings
func NewSettings(database *gorm.DB) *Settings {
	var s *Settings
	s = &Settings{DB: database}
	return s
}

// EmptyValue creates an emtpy value
func (conf *Settings) EmptyValue(service, name, typeValue string) SettingValue {
	return SettingValue{
		Name:    name,
		Service: service,
		Type:    typeValue,
		String:  "",
		Integer: int64(0),
		Boolean: false,
	}
}

// NewValue creates a new settings value
func (conf *Settings) NewValue(service, name, typeValue string, value interface{}) error {
	// Empty new value
	entry := conf.EmptyValue(service, name, typeValue)
	switch typeValue {
	case TypeBoolean:
		entry.Boolean = value.(bool)
	case TypeInteger:
		entry.Integer = value.(int64)
	case TypeString:
		entry.String = value.(string)
	}
	// Create record in database
	if conf.DB.NewRecord(entry) {
		if err := conf.DB.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create NewValue %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// NewStringValue creates a new settings value
func (conf *Settings) NewStringValue(service, name, value string) error {
	return conf.NewValue(service, name, TypeString, value)
}

// NewBooleanValue creates a new settings value
func (conf *Settings) NewBooleanValue(service, name string, value bool) error {
	return conf.NewValue(service, name, TypeBoolean, value)
}

// NewIntegerValue creates a new settings value
func (conf *Settings) NewIntegerValue(service, name string, value int64) error {
	return conf.NewValue(service, name, TypeInteger, value)
}

// DeleteValue deletes an existing settings value
func (conf *Settings) DeleteValue(service, name string) error {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("DeleteValue %v", err)
	}
	if err := conf.DB.Unscoped().Delete(&value).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
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
func (conf *Settings) RetrieveValues(service string) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("service = ?", service).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValue retrieves one value from settings by service and name from backend
func (conf *Settings) RetrieveValue(service, name string) (SettingValue, error) {
	var value SettingValue
	if err := conf.DB.Where("service = ?", service).Where("name = ?", name).First(&value).Error; err != nil {
		return SettingValue{}, err
	}
	return value, nil
}

// GetMap returns the map of values by service
func (conf *Settings) GetMap(service string) (MapSettings, error) {
	all, err := conf.RetrieveValues(service)
	if err != nil {
		return MapSettings{}, fmt.Errorf("error getting values %v", err)
	}
	_map := make(MapSettings)
	for _, c := range all {
		_map[c.Name] = c
	}
	return _map, nil
}

// GetValue gets one value from settings by service and name
func (conf *Settings) GetValue(service, name string) (SettingValue, error) {
	return conf.RetrieveValue(service, name)
}

// SetInteger sets a numeric settings value by service and name
func (conf *Settings) SetInteger(intValue int64, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetInteger %d %v", intValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update(TypeInteger, intValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetInteger %d %s %s", intValue, service, name)
	return nil
}

// GetInteger gets a numeric settings value by service and name
func (conf *Settings) GetInteger(service, name string) (int64, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return 0, err
	}
	return value.Integer, nil
}

// SetBoolean sets a boolean settings value by service and name
func (conf *Settings) SetBoolean(boolValue bool, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetBoolean %v %v", boolValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Updates(map[string]interface{}{TypeBoolean: boolValue}).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetBoolean %v %s %s", boolValue, service, name)
	return nil
}

// GetBoolean gets a boolean settings value by service and name
func (conf *Settings) GetBoolean(service, name string) (bool, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false, err
	}
	return value.Boolean, nil
}

// GetString gets a string settings value by service and name
func (conf *Settings) GetString(service, name string) (string, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return "", err
	}
	return value.String, nil
}

// SetString sets a boolean settings value by service and name
func (conf *Settings) SetString(strValue string, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetString %s %v", strValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update(TypeString, strValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetString %s %s %s", strValue, service, name)
	return nil
}

// IsValue checks if a settings value exists by service and name
func (conf *Settings) IsValue(service, name string) bool {
	_, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false
	}
	return true
}

// DebugHTTP checks if http debugging is enabled by service
func (conf *Settings) DebugHTTP(service string) bool {
	value, err := conf.RetrieveValue(service, DebugHTTP)
	if err != nil {
		return false
	}
	return value.Boolean
}

// DebugService checks if debugging is enabled by service
func (conf *Settings) DebugService(service string) bool {
	value, err := conf.RetrieveValue(service, DebugService)
	if err != nil {
		return false
	}
	return value.Boolean
}

// ServiceMetrics checks if metrics are enabled by service
func (conf *Settings) ServiceMetrics(service string) bool {
	value, err := conf.RetrieveValue(service, ServiceMetrics)
	if err != nil {
		return false
	}
	return value.Boolean
}

// RefreshEnvs gets the interval in seconds to refresh environments by service
func (conf *Settings) RefreshEnvs(service string) int64 {
	value, err := conf.RetrieveValue(service, RefreshEnvs)
	if err != nil {
		return 0
	}
	return value.Integer
}

// RefreshSettings gets the interval in seconds to refresh settings by service
func (conf *Settings) RefreshSettings(service string) int64 {
	value, err := conf.RetrieveValue(service, RefreshSettings)
	if err != nil {
		return 0
	}
	return value.Integer
}

// CleanupSessions gets the interval in seconds to cleanup expired sessions by service
func (conf *Settings) CleanupSessions() int64 {
	value, err := conf.RetrieveValue(ServiceAdmin, CleanupSessions)
	if err != nil {
		return 0
	}
	return value.Integer
}

// DefaultEnv gets the default environment
// FIXME customize the fallover one
func (conf *Settings) DefaultEnv(service string) string {
	value, err := conf.RetrieveValue(service, DefaultEnv)
	if err != nil {
		return "dev"
	}
	return value.String
}
