package configuration

import (
	"fmt"
	"log"

	"github.com/jinzhu/gorm"
)

// Types of configuration values
const (
	TypeString  = "string"
	TypeBoolean = "boolean"
	TypeInteger = "integer"
)

// Names for configuration values
const (
	FieldDebugHTTP = "debug_http"
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

// ServiceValues to have all configuration values by service
type ServiceValues map[string][]ConfigValue

// Configuration keeps al configuration values
type Configuration struct {
	DB     *gorm.DB
	Values []ConfigValue
	//Service ServiceValues
}

// NewConfiguration to initialize the access to configuration
func NewConfiguration(database *gorm.DB) *Configuration {
	var s *Configuration
	s = &Configuration{DB: database, Values: nil}
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
func (conf *Configuration) NewValue(service, name, typeValue string, values TypedValues) error {
	// Empty new value
	entry := conf.EmptyValue(service, name, typeValue)
	entry.Integer = values[TypeInteger].(int64)
	entry.Boolean = values[TypeBoolean].(bool)
	entry.String = values[TypeString].(string)
	// Create record in database
	if conf.DB.NewRecord(entry) {
		if err := conf.DB.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create NewValue %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	// Reload values since they have changed
	return conf.ReloadValues()
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
	return conf.ReloadValues()
}

// GetAllValues gets all configuration values
func (conf *Configuration) GetAllValues() ([]ConfigValue, error) {
	return conf.Values, nil
}

// SetAllValues sets all configuration values
func (conf *Configuration) SetAllValues(values []ConfigValue) error {
	conf.Values = values
	return nil
}

// ReloadValues reloads all values from backend
func (conf *Configuration) ReloadValues() error {
	var values []ConfigValue
	if err := conf.DB.Find(&values).Error; err != nil {
		return err
	}
	conf.Values = values
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
	for _, v := range conf.Values {
		if v.Service == service && v.Name == name {
			return v, nil
		}
	}
	return ConfigValue{}, fmt.Errorf("configuration value not found")
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
	return conf.ReloadValues()
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
	if err := conf.DB.Model(&value).Update(TypeBoolean, boolValue).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	log.Printf("SetBoolean %v %s %s", boolValue, service, name)
	return conf.ReloadValues()
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
	return conf.ReloadValues()
}

// IsValue checks if a configuration value exists by service and name
func (conf *Configuration) IsValue(service, name string) bool {
	_, err := conf.RetrieveValue(service, name)
	if err != nil {
		return false
	}
	return true
}

// DebugHTTP checks if debugging is enabled by service
func (conf *Configuration) DebugHTTP(service string) bool {
	value, err := conf.RetrieveValue(service, FieldDebugHTTP)
	if err != nil {
		return false
	}
	return value.Boolean
}
