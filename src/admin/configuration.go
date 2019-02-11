package main

import (
	"fmt"
	"log"

	"github.com/jinzhu/gorm"
)

// Types of configuration values
const (
	typeString  = "string"
	typeBoolean = "boolean"
	typeInteger = "integer"
)

// Names for configuration values
const (
	DebugHTTP = "debug_http"
)

// ConfigurationValue to hold each value for configuration
type ConfigurationValue struct {
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

// ServiceValues to have all configuration values by service
type ServiceValues map[string][]ConfigurationValue

// ServiceConfiguration to all configuration values
type ServiceConfiguration struct {
	db     *gorm.DB
	Values []ConfigurationValue
	//Service ServiceValues
}

// NewServiceConfiguration to initialize the access to configuration
func NewServiceConfiguration(database *gorm.DB) (*ServiceConfiguration, error) {
	var s *ServiceConfiguration
	s = &ServiceConfiguration{db: database, Values: nil}
	err := s.ReloadValues()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// EmptyValue creates an emtpy value
func (conf *ServiceConfiguration) EmptyValue(service, name, typeValue string) ConfigurationValue {
	return ConfigurationValue{
		Name:    name,
		Service: service,
		Type:    typeValue,
		String:  "",
		Integer: 0,
		Boolean: false,
	}
}

// NewValue creates a new configuration value
func (conf *ServiceConfiguration) NewValue(service, name, typeValue string, values TypedValues) error {
	// Empty new value
	entry := conf.EmptyValue(service, name, typeValue)
	entry.Integer = values[typeInteger].(int64)
	entry.Boolean = values[typeBoolean].(bool)
	entry.String = values[typeString].(string)
	// Create record in database
	if conf.db.NewRecord(entry) {
		if err := conf.db.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create NewValue %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	// Reload values since they have changed
	return conf.ReloadValues()
}

// NewStringValue creates a new configuration value
func (conf *ServiceConfiguration) NewStringValue(service, name, value string) error {
	entry := make(TypedValues)
	entry[typeString] = value
	return conf.NewValue(service, name, typeString, entry)
}

// NewBooleanValue creates a new configuration value
func (conf *ServiceConfiguration) NewBooleanValue(service, name string, value bool) error {
	entry := make(TypedValues)
	entry[typeBoolean] = value
	return conf.NewValue(service, name, typeBoolean, entry)
}

// NewIntegerValue creates a new configuration value
func (conf *ServiceConfiguration) NewIntegerValue(service, name string, value int64) error {
	entry := make(TypedValues)
	entry[typeInteger] = value
	return conf.NewValue(service, name, typeInteger, entry)
}

// DeleteValue deletes an existing configuration value
func (conf *ServiceConfiguration) DeleteValue(service, name string) error {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("DeleteValue %v", err)
	}
	if err := conf.db.Delete(&value).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return conf.ReloadValues()
}

// GetAllValues gets all configuration values
func (conf *ServiceConfiguration) GetAllValues() ([]ConfigurationValue, error) {
	return conf.Values, nil
}

// SetAllValues sets all configuration values
func (conf *ServiceConfiguration) SetAllValues(values []ConfigurationValue) error {
	conf.Values = values
	return nil
}

// ReloadValues reloads all values from backend
func (conf *ServiceConfiguration) ReloadValues() error {
	var values []ConfigurationValue
	if err := conf.db.Find(&values).Error; err != nil {
		return err
	}
	conf.Values = values
	return nil
}

// RetrieveAllValues retrieves and returns all values from backend
func (conf *ServiceConfiguration) RetrieveAllValues() ([]ConfigurationValue, error) {
	var values []ConfigurationValue
	if err := conf.db.Find(&values).Error; err != nil {
		return values, err
	}
	return values, nil
}

// RetrieveValue retrieves one value from configuration by service and name from backend
func (conf *ServiceConfiguration) RetrieveValue(service, name string) (ConfigurationValue, error) {
	var value ConfigurationValue
	if err := conf.db.Where("service = ?", service).Where("name = ?", name).First(&value).Error; err != nil {
		return ConfigurationValue{}, err
	}
	return value, nil
}

// GetValue gets one value from configuration by service and name
func (conf *ServiceConfiguration) GetValue(service, name string) (ConfigurationValue, error) {
	for _, v := range conf.Values {
		if v.Service == service && v.Name == name {
			return v, nil
		}
	}
	return ConfigurationValue{}, fmt.Errorf("configuration value not found")
}

// SetInteger sets a numeric configuration value by service and name
func (conf *ServiceConfiguration) SetInteger(intValue int64, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetInteger %d %v", intValue, err)
	}
	// Update
	if err := conf.db.Model(&value).Update(typeInteger, intValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetInteger %d %s %s", intValue, service, name)
	return conf.ReloadValues()
}

// GetInteger gets a numeric configuration value by service and name
func (conf *ServiceConfiguration) GetInteger(service, name string) (int64, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return 0, err
	}
	return value.Integer, nil
}

// SetBoolean sets a boolean configuration value by service and name
func (conf *ServiceConfiguration) SetBoolean(boolValue bool, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetBoolean %v %v", boolValue, err)
	}
	// Update
	if err := conf.db.Model(&value).Update(typeBoolean, boolValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetBoolean %v %s %s", boolValue, service, name)
	return conf.ReloadValues()
}

// GetBoolean gets a boolean configuration value by service and name
func (conf *ServiceConfiguration) GetBoolean(service, name string) (bool, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false, err
	}
	return value.Boolean, nil
}

// GetString gets a string configuration value by service and name
func (conf *ServiceConfiguration) GetString(service, name string) (string, error) {
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return "", err
	}
	return value.String, nil
}

// SetString sets a boolean configuration value by service and name
func (conf *ServiceConfiguration) SetString(strValue string, service, name string) error {
	// Retrieve current value
	value, err := conf.RetrieveValue(service, name)
	if err != nil {
		return fmt.Errorf("SetString %s %v", strValue, err)
	}
	// Update
	if err := conf.db.Model(&value).Update(typeString, strValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetString %s %s %s", strValue, service, name)
	return conf.ReloadValues()
}

// IsValue checks if a configuration value exists by service and name
func (conf *ServiceConfiguration) IsValue(service, name string) bool {
	_, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false
	}
	return true
}

// DebugHTTP checks if debugging is enabled by service
func (conf *ServiceConfiguration) DebugHTTP(service string) bool {
	value, err := conf.RetrieveValue(service, DebugHTTP)
	if err != nil {
		return false
	}
	return value.Boolean
}
