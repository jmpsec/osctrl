package settings

import (
	"fmt"

	"github.com/jmpsec/osctrl/types"
	"gorm.io/gorm"

	"github.com/rs/zerolog/log"
)

// Types of services
const (
	ServiceTLS   string = "tls"
	ServiceAdmin string = "admin"
	ServiceAPI   string = "api"
)

// Types of settings values
const (
	TypeString  string = "string"
	TypeBoolean string = "boolean"
	TypeInteger string = "integer"
)

// Types of authentication
const (
	AuthNone  string = "none"
	AuthJSON  string = "json"
	AuthDB    string = "db"
	AuthSAML  string = "saml"
	AuthJWT   string = "jwt"
	AuthOAuth string = "oauth"
	AuthOIDC  string = "oidc"
)

// Types of logging
const (
	LoggingNone     string = "none"
	LoggingStdout   string = "stdout"
	LoggingFile     string = "file"
	LoggingDB       string = "db"
	LoggingGraylog  string = "graylog"
	LoggingSplunk   string = "splunk"
	LoggingLogstash string = "logstash"
	LoggingKinesis  string = "kinesis"
	LoggingS3       string = "s3"
	LoggingKafka    string = "kafka"
	LoggingElastic  string = "elastic"
)

// Types of carver
const (
	CarverLocal string = "local"
	CarverDB    string = "db"
	CarverS3    string = "s3"
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
	DebugHTTP          string = "debug_http"
	DebugService       string = "debug_service"
	RefreshEnvs        string = "refresh_envs"
	RefreshSettings    string = "refresh_settings"
	CleanupSessions    string = "cleanup_sessions"
	CleanupExpired     string = "cleanup_expired"
	ServiceMetrics     string = "service_metrics"
	MetricsHost        string = "metrics_host"
	MetricsPort        string = "metrics_port"
	MetricsProtocol    string = "metrics_protocol"
	InactiveHours      string = "inactive_hours"
	AcceleratedSeconds string = "accelerated_seconds"
	NodeDashboard      string = "node_dashboard"
	OnelinerExpiration string = "oneliner_expiration"
)

// Names for the values that are read from the JSON config file
const (
	JSONListener   string = "json_listener"
	JSONPort       string = "json_port"
	JSONHost       string = "json_host"
	JSONAuth       string = "json_auth"
	JSONLogger     string = "json_logger"
	JSONCarver     string = "json_carver"
	JSONSessionKey string = "json_sessionkey"
)

// Values for generic IDs
const (
	NoEnvironmentID = iota
)

// SettingValue to hold each value for settings
type SettingValue struct {
	gorm.Model
	Name          string `gorm:"index"`
	Service       string
	EnvironmentID uint
	JSON          bool
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

// ValidTypes to check validity of settings type
var ValidTypes = map[string]struct{}{
	TypeString:  struct{}{},
	TypeBoolean: struct{}{},
	TypeInteger: struct{}{},
}

// ValidServices to check validity of settings service
var ValidServices = map[string]struct{}{
	ServiceTLS:   struct{}{},
	ServiceAdmin: struct{}{},
	ServiceAPI:   struct{}{},
}

// NewSettings to initialize the access to settings and table
func NewSettings(backend *gorm.DB) *Settings {
	var s *Settings
	s = &Settings{DB: backend}
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
		JSON:          false,
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
		return fmt.Errorf("Create NewValue %v", err)
	}
	return nil
}

// NewJSON creates a new JSON value
func (conf *Settings) NewJSON(service, name, value string, envID uint) error {
	// Empty new JSON value
	entry := conf.EmptyValue(service, name, TypeString, envID)
	entry.JSON = true
	entry.String = value
	// Create record in database
	if err := conf.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("Create NewJSON %v", err)
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

// VerifyType to make sure type is valid
func (conf *Settings) VerifyType(sType string) bool {
	_, ok := ValidTypes[sType]
	return ok
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
		return fmt.Errorf("DeleteValue %v", err)
	}
	if err := conf.DB.Unscoped().Delete(&value).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// RetrieveAllValues retrieves and returns all values excepting JSON from backend
func (conf *Settings) RetrieveAllValues() ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("json = ?", false).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveAllEnvValues retrieves and returns all values excepting JSON from backend
func (conf *Settings) RetrieveAllEnvValues(envID uint) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("json = ? AND environment_id = ?", false, envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveAll retrieves and returns all values from backend
func (conf *Settings) RetrieveAll() ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveAllEnv retrieves and returns all values from backend per environment
func (conf *Settings) RetrieveAllEnv(envID uint) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("environment_id = ?", envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveAllJSON retrieves and returns all JSON values from backend
func (conf *Settings) RetrieveAllJSON(service string) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("service = ? AND json = ?", service, true).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveAllEnvJSON retrieves and returns all JSON values from backend
func (conf *Settings) RetrieveAllEnvJSON(service string, envID uint) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("service = ? AND json = ? AND environment_id = ?", service, true, envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// SetJSON sets the JSON configuration value
func (conf *Settings) SetJSON(service, name, value string, envID uint) error {
	if !conf.IsJSON(service, name, envID) {
		if err := conf.NewJSON(service, name, value, envID); err != nil {
			return err
		}
	} else {
		if err := conf.SetString(value, service, name, true, envID); err != nil {
			return err
		}
	}
	return nil
}

// SetTLSJSON sets all the JSON configuration values for TLS service
func (conf *Settings) SetTLSJSON(cfg types.JSONConfigurationTLS, envID uint) error {
	if err := conf.SetJSON(ServiceTLS, JSONListener, cfg.Listener, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceTLS, JSONPort, cfg.Port, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceTLS, JSONHost, cfg.Host, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceTLS, JSONAuth, cfg.Auth, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceTLS, JSONLogger, cfg.Logger, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceTLS, JSONCarver, cfg.Carver, envID); err != nil {
		return err
	}
	return nil
}

// SetAdminJSON sets all the JSON configuration values for admin service
func (conf *Settings) SetAdminJSON(cfg types.JSONConfigurationAdmin, envID uint) error {
	if err := conf.SetJSON(ServiceAdmin, JSONListener, cfg.Listener, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAdmin, JSONPort, cfg.Port, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAdmin, JSONHost, cfg.Host, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAdmin, JSONAuth, cfg.Auth, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAdmin, JSONLogger, cfg.Logger, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAdmin, JSONSessionKey, cfg.SessionKey, envID); err != nil {
		return err
	}
	return nil
}

// SetAPIJSON sets all the JSON configuration values for API service
func (conf *Settings) SetAPIJSON(cfg types.JSONConfigurationAPI, envID uint) error {
	if err := conf.SetJSON(ServiceAPI, JSONListener, cfg.Listener, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAPI, JSONPort, cfg.Port, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAPI, JSONHost, cfg.Host, envID); err != nil {
		return err
	}
	if err := conf.SetJSON(ServiceAPI, JSONAuth, cfg.Auth, envID); err != nil {
		return err
	}
	return nil
}

// RetrieveValues retrieves and returns all values from backend
func (conf *Settings) RetrieveValues(service string, jsonSetting bool, envID uint) ([]SettingValue, error) {
	var values []SettingValue
	if err := conf.DB.Where("service = ? AND json = ? AND environment_id = ?", service, jsonSetting, envID).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValue retrieves one value from settings by service and name from backend
func (conf *Settings) RetrieveValue(service, name string, envID uint) (SettingValue, error) {
	var value SettingValue
	if err := conf.DB.Where("json = ? AND service = ? AND environment_id = ?", false, service, envID).Where("name = ?", name).First(&value).Error; err != nil {
		return SettingValue{}, err
	}
	return value, nil
}

// RetrieveJSON retrieves one JSON value from settings by service and name from backend
func (conf *Settings) RetrieveJSON(service, name string, envID uint) (SettingValue, error) {
	var value SettingValue
	if err := conf.DB.Where("json = ? AND service = ? AND environment_id = ?", true, service, envID).Where("name = ?", name).First(&value).Error; err != nil {
		return SettingValue{}, err
	}
	return value, nil
}

// GetMap returns the map of values by service, excluding JSON
func (conf *Settings) GetMap(service string, envID uint) (MapSettings, error) {
	all, err := conf.RetrieveValues(service, false, envID)
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
func (conf *Settings) GetValue(service, name string, envID uint) (SettingValue, error) {
	return conf.RetrieveValue(service, name, envID)
}

// SetInteger sets a numeric settings value by service and name
func (conf *Settings) SetInteger(intValue int64, service, name string, envID uint) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("SetInteger %d %v", intValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update(TypeInteger, intValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
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
		return fmt.Errorf("SetBoolean %v %v", boolValue, err)
	}
	// Update
	if err := conf.DB.Model(&value).Updates(map[string]interface{}{TypeBoolean: boolValue}).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Debug().Msgf("SetBoolean %v %s %s", boolValue, service, name)
	return nil
}

// GetBoolean gets a boolean settings value by service and name
func (conf *Settings) GetBoolean(service, name string, envID uint) (bool, error) {
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return false, err
	}
	return value.Boolean, nil
}

// GetString gets a string settings value by service and name
func (conf *Settings) GetString(service, name string, envID uint) (string, error) {
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return "", err
	}
	return value.String, nil
}

// SetString sets a boolean settings value by service and name
func (conf *Settings) SetString(strValue string, service, name string, _json bool, envID uint) error {
	var err error
	var val SettingValue
	// Retrieve current value
	if _json {
		val, err = conf.RetrieveJSON(service, name, envID)
		if err != nil {
			return fmt.Errorf("SetString %s %v", strValue, err)
		}
	} else {
		val, err = conf.RetrieveValue(service, name, envID)
		if err != nil {
			return fmt.Errorf("SetString %s %v", strValue, err)
		}
	}
	// Update
	if err := conf.DB.Model(&val).Update(TypeString, strValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Debug().Msgf("SetString %s %s %s", strValue, service, name)
	return nil
}

// GetInfo gets the info of a setting
func (conf *Settings) GetInfo(service, name string, envID uint) (string, error) {
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return "", err
	}
	return value.Info, nil
}

// SetInfo sets the info of a setting
func (conf *Settings) SetInfo(info string, service, name string, envID uint) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return fmt.Errorf("SetInfo %s %v", info, err)
	}
	// Update
	if err := conf.DB.Model(&value).Update("info", info).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Debug().Msgf("SetInfo %s %s %s", info, service, name)
	return nil
}

// IsValue checks if a settings value exists by service and name
func (conf *Settings) IsValue(service, name string, envID uint) bool {
	_, err := conf.RetrieveValue(service, name, envID)
	if err != nil {
		return false
	}
	return true
}

// IsJSON checks if a JSON value exists by service and name
func (conf *Settings) IsJSON(service, name string, envID uint) bool {
	_, err := conf.RetrieveJSON(service, name, envID)
	if err != nil {
		return false
	}
	return true
}

// DebugHTTP checks if http debugging is enabled by service
func (conf *Settings) DebugHTTP(service string, envID uint) bool {
	value, err := conf.RetrieveValue(service, DebugHTTP, envID)
	if err != nil {
		return false
	}
	return value.Boolean
}

// DebugService checks if debugging is enabled by service
func (conf *Settings) DebugService(service string) bool {
	value, err := conf.RetrieveValue(service, DebugService, NoEnvironmentID)
	if err != nil {
		return false
	}
	return value.Boolean
}

// ServiceMetrics checks if metrics are enabled by service
func (conf *Settings) ServiceMetrics(service string) bool {
	value, err := conf.RetrieveValue(service, ServiceMetrics, NoEnvironmentID)
	if err != nil {
		return false
	}
	return value.Boolean
}

// RefreshEnvs gets the interval in seconds to refresh environments by service
func (conf *Settings) RefreshEnvs(service string) int64 {
	value, err := conf.RetrieveValue(service, RefreshEnvs, NoEnvironmentID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// RefreshSettings gets the interval in seconds to refresh settings by service
func (conf *Settings) RefreshSettings(service string) int64 {
	value, err := conf.RetrieveValue(service, RefreshSettings, NoEnvironmentID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// CleanupSessions gets the interval in seconds to cleanup expired sessions by service
func (conf *Settings) CleanupSessions() int64 {
	value, err := conf.RetrieveValue(ServiceAdmin, CleanupSessions, NoEnvironmentID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// CleanupExpired gets the interval in seconds to cleanup expired queries and carves
func (conf *Settings) CleanupExpired() int64 {
	value, err := conf.RetrieveValue(ServiceAdmin, CleanupExpired, NoEnvironmentID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// InactiveHours gets the value in hours for a node to be inactive by service
func (conf *Settings) InactiveHours(envID uint) int64 {
	value, err := conf.RetrieveValue(ServiceAdmin, InactiveHours, envID)
	if err != nil {
		return 0
	}
	return value.Integer
}

// NodeDashboard checks if display dashboard per node is enabled
func (conf *Settings) NodeDashboard(envID uint) bool {
	value, err := conf.RetrieveValue(ServiceAdmin, NodeDashboard, envID)
	if err != nil {
		return false
	}
	return value.Boolean
}

// OnelinerExpiration checks if enrolling links will expire
func (conf *Settings) OnelinerExpiration(envID uint) bool {
	value, err := conf.RetrieveValue(ServiceTLS, OnelinerExpiration, envID)
	if err != nil {
		return false
	}
	return value.Boolean
}
