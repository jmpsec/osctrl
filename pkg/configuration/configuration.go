package configuration

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

// Types of configuration values
const (
	TypeString  string = "string"
	TypeBoolean string = "boolean"
	TypeInteger string = "integer"
)

// Names for configuration values
const (
	DebugHTTP       string = "debug_http"
	DebugService    string = "debug_service"
	RefreshContexts string = "refresh_contexts"
	ServiceMetrics  string = "service_metrics"
	MetricsHost     string = "metrics_host"
	MetricsPort     string = "metrics_port"
	MetricsProtocol string = "metrics_protocol"
)

// ConfigValue to hold each value for configuration
type ConfigValue struct {
	gorm.Model
	Name    string `gorm:"index"`
	Service string
	Type    string
	String  string
	Boolean bool
	Integer int64
}

// TypedValues to have each value by type
type TypedValues map[string]interface{}

// Configuration keeps al configuration values
type Configuration struct {
	DB *gorm.DB
}

// NewConfiguration to initialize the access to configuration
func NewConfiguration(database *gorm.DB) *Configuration {
	var s *Configuration
	s = &Configuration{DB: database}
	return s
}

// EmptyValue creates an emtpy value
func (conf *Configuration) EmptyValue(service, name, typeValue string) ConfigValue {
	return ConfigValue{
		Name:    name,
		Service: service,
		Type:    typeValue,
		String:  "",
		Integer: int64(0),
		Boolean: false,
	}
}

// NewValue creates a new configuration value
func (conf *Configuration) NewValue(service, name, typeValue string, value TypedValues) error {
	// Empty new value
	entry := conf.EmptyValue(service, name, typeValue)
	switch typeValue {
	case TypeBoolean:
		entry.Boolean = value[TypeBoolean].(bool)
	case TypeInteger:
		entry.Integer = value[TypeInteger].(int64)
	case TypeString:
		entry.String = value[TypeString].(string)
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

// NewStringValue creates a new configuration value
func (conf *Configuration) NewStringValue(service, name, value string) error {
	entry := make(TypedValues)
	entry[TypeString] = value
	entry[TypeInteger] = int64(0)
	entry[TypeBoolean] = false
	return conf.NewValue(service, name, TypeString, entry)
}

// NewBooleanValue creates a new configuration value
func (conf *Configuration) NewBooleanValue(service, name string, value bool) error {
	entry := make(TypedValues)
	entry[TypeBoolean] = value
	entry[TypeInteger] = int64(0)
	entry[TypeString] = ""
	return conf.NewValue(service, name, TypeBoolean, entry)
}

// NewIntegerValue creates a new configuration value
func (conf *Configuration) NewIntegerValue(service, name string, value int64) error {
	entry := make(TypedValues)
	entry[TypeInteger] = value
	entry[TypeBoolean] = false
	entry[TypeString] = ""
	return conf.NewValue(service, name, TypeInteger, entry)
}

// DeleteValue deletes an existing configuration value
func (conf *Configuration) DeleteValue(service, name string) error {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("DeleteValue %v", err)
	}
	if err := conf.DB.Delete(&value).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// RetrieveAllValues retrieves and returns all values from backend
func (conf *Configuration) RetrieveAllValues() ([]ConfigValue, error) {
	var values []ConfigValue
	if err := conf.DB.Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveServiceValues retrieves and returns all values from backend
func (conf *Configuration) RetrieveServiceValues(service string) ([]ConfigValue, error) {
	var values []ConfigValue
	if err := conf.DB.Where("service = ?", service).Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValue retrieves one value from configuration by service and name from backend
func (conf *Configuration) RetrieveValue(service, name string) (ConfigValue, error) {
	var value ConfigValue
	if err := conf.DB.Where("service = ?", service).Where("name = ?", name).First(&value).Error; err != nil {
		return ConfigValue{}, err
	}
	return value, nil
}

// GetValue gets one value from configuration by service and name
func (conf *Configuration) GetValue(service, name string) (ConfigValue, error) {
	return conf.RetrieveValue(service, name)
}

// SetInteger sets a numeric configuration value by service and name
func (conf *Configuration) SetInteger(intValue int64, service, name string) error {
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

// GetInteger gets a numeric configuration value by service and name
func (conf *Configuration) GetInteger(service, name string) (int64, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return 0, err
	}
	return value.Integer, nil
}

// SetBoolean sets a boolean configuration value by service and name
func (conf *Configuration) SetBoolean(boolValue bool, service, name string) error {
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

// GetBoolean gets a boolean configuration value by service and name
func (conf *Configuration) GetBoolean(service, name string) (bool, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false, err
	}
	return value.Boolean, nil
}

// GetString gets a string configuration value by service and name
func (conf *Configuration) GetString(service, name string) (string, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return "", err
	}
	return value.String, nil
}

// SetString sets a boolean configuration value by service and name
func (conf *Configuration) SetString(strValue string, service, name string) error {
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

// IsValue checks if a configuration value exists by service and name
func (conf *Configuration) IsValue(service, name string) bool {
	_, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false
	}
	return true
}

// DebugHTTP checks if http debugging is enabled by service
func (conf *Configuration) DebugHTTP(service string) bool {
	value, err := conf.RetrieveValue(service, DebugHTTP)
	if err != nil {
		return false
	}
	return value.Boolean
}

// DebugService checks if debugging is enabled by service
func (conf *Configuration) DebugService(service string) bool {
	value, err := conf.RetrieveValue(service, DebugService)
	if err != nil {
		return false
	}
	return value.Boolean
}

// ServiceMetrics checks if metrics are enabled by service
func (conf *Configuration) ServiceMetrics(service string) bool {
	value, err := conf.RetrieveValue(service, ServiceMetrics)
	if err != nil {
		return false
	}
	return value.Boolean
}

// RefreshContexts checks if metrics are enabled by service
func (conf *Configuration) RefreshContexts(service string) int64 {
	value, err := conf.RetrieveValue(service, ServiceMetrics)
	if err != nil {
		return 0
	}
	return value.Integer
}
