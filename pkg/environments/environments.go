package environments

import (
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
)

const (
	// DefaultEnrollPath as default value for enrolling nodes
	DefaultEnrollPath string = "enroll"
	// DefaultLogPath as default value for logging data from nodes
	DefaultLogPath string = "log"
	// DefaultLogInterval as default interval for logging data from nodes
	DefaultLogInterval int = 10
	// DefaultConfigPath as default value for configuring nodes
	DefaultConfigPath string = "config"
	// DefaultConfigInterval as default interval for configuring nodes
	DefaultConfigInterval int = 10
	// DefaultQueryReadPath as default value for distributing on-demand queries to nodes
	DefaultQueryReadPath string = "read"
	// DefaultQueryWritePath as default value for collecting results from on-demand queries
	DefaultQueryWritePath string = "write"
	// DefaultQueryInterval as default interval for distributing on-demand queries to nodes
	DefaultQueryInterval int = 10
	// DefaultCarverInitPath as default init endpoint for the carver
	DefaultCarverInitPath string = "init"
	// DefaultCarverBlockPath as default block endpoint for the carver
	DefaultCarverBlockPath string = "block"
	// DefaultEnvironmentIcon as default icon to use for environments
	DefaultEnvironmentIcon string = "fas fa-wrench"
	// DefaultEnvironmentType as default type to use for environments
	DefaultEnvironmentType string = "osquery"
	// DefaultSecretLength as default length for secrets
	DefaultSecretLength int = 64
	// DefaultLinkExpire as default time in hours to expire enroll/remove links
	DefaultLinkExpire int = 24
)

// TLSEnvironment to hold each of the TLS environment
type TLSEnvironment struct {
	gorm.Model
	Name             string `gorm:"index"`
	Hostname         string
	Secret           string
	EnrollSecretPath string
	EnrollExpire     time.Time
	RemoveSecretPath string
	RemoveExpire     time.Time
	Type             string
	DebugHTTP        bool
	Icon             string
	Configuration    string
	Certificate      string
	ConfigInterval   int
	LogInterval      int
	QueryInterval    int
	EnrollPath       string
	LogPath          string
	ConfigPath       string
	QueryReadPath    string
	QueryWritePath   string
	CarverInitPath   string
	CarverBlockPath  string
}

// MapEnvironments to hold the TLS environments by name
type MapEnvironments map[string]TLSEnvironment

// Environment keeps all TLS  Environments
type Environment struct {
	DB *gorm.DB
}

// CreateEnvironment to initialize the environment struct
func CreateEnvironment(backend *gorm.DB) *Environment {
	var e *Environment
	e = &Environment{DB: backend}
	return e
}

// Get TLS Environment by name
func (environment *Environment) Get(name string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("name = ?", name).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Empty generates an empty TLSEnvironment with default values
func (environment *Environment) Empty(name, hostname string) TLSEnvironment {
	return TLSEnvironment{
		Name:             name,
		Hostname:         hostname,
		Secret:           generateRandomString(DefaultSecretLength),
		EnrollSecretPath: generateKSUID(),
		RemoveSecretPath: generateKSUID(),
		EnrollExpire:     time.Now(),
		RemoveExpire:     time.Now(),
		Type:             DefaultEnvironmentType,
		DebugHTTP:        false,
		Icon:             DefaultEnvironmentIcon,
		Configuration:    "",
		Certificate:      "",
		ConfigInterval:   DefaultConfigInterval,
		LogInterval:      DefaultLogInterval,
		QueryInterval:    DefaultQueryInterval,
		EnrollPath:       DefaultEnrollPath,
		LogPath:          DefaultLogPath,
		ConfigPath:       DefaultConfigPath,
		QueryReadPath:    DefaultQueryReadPath,
		QueryWritePath:   DefaultQueryWritePath,
		CarverInitPath:   DefaultCarverInitPath,
		CarverBlockPath:  DefaultCarverBlockPath,
	}
}

// Create new TLS Environment
func (environment *Environment) Create(env TLSEnvironment) error {
	if environment.DB.NewRecord(env) {
		if err := environment.DB.Create(&env).Error; err != nil {
			return fmt.Errorf("Create TLS Environment %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Exists checks if TLS Environment exists already
func (environment *Environment) Exists(name string) bool {
	var results int
	environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// All gets all TLS Environment
func (environment *Environment) All() ([]TLSEnvironment, error) {
	var envs []TLSEnvironment
	if err := environment.DB.Find(&envs).Error; err != nil {
		return envs, err
	}
	return envs, nil
}

// GetMap returns the map of environments by name
func (environment *Environment) GetMap() (MapEnvironments, error) {
	all, err := environment.All()
	if err != nil {
		return MapEnvironments{}, fmt.Errorf("error getting environments %v", err)
	}
	_map := make(MapEnvironments)
	for _, e := range all {
		_map[e.Name] = e
	}
	return _map, nil
}

// Delete TLS Environment by name
func (environment *Environment) Delete(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Unscoped().Delete(&env).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// Update TLS Environment
func (environment *Environment) Update(e TLSEnvironment) error {
	env, err := environment.Get(e.Name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Model(&env).Updates(e).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// UpdateConfiguration to update configuration for a environment
func (environment *Environment) UpdateConfiguration(name, configuration string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Model(&env).Update("configuration", configuration).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// UpdateIntervals to update intervals for a environment
func (environment *Environment) UpdateIntervals(name string, csecs, lsecs, qsecs int) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	updated := env
	updated.ConfigInterval = csecs
	updated.LogInterval = lsecs
	updated.QueryInterval = qsecs
	if err := environment.DB.Model(&env).Updates(updated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateSecrets to replace Secret and SecretPath for a environment
func (environment *Environment) RotateSecrets(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	rotated := env
	rotated.Secret = generateRandomString(DefaultSecretLength)
	rotated.EnrollSecretPath = generateKSUID()
	rotated.RemoveSecretPath = generateKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateEnrollPath to replace SecretPath for enrolling in a environment
func (environment *Environment) RotateEnrollPath(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	rotated := env
	rotated.EnrollSecretPath = generateKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateSecret to replace the current Secret for a environment
func (environment *Environment) RotateSecret(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	rotated := env
	rotated.Secret = generateRandomString(DefaultSecretLength)
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// ExpireEnroll to expire the enroll in a environment
func (environment *Environment) ExpireEnroll(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Model(&env).Update("enroll_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// RotateRemove to replace Secret and SecrtPath for enrolling in a environment
func (environment *Environment) RotateRemove(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	rotated := env
	rotated.RemoveSecretPath = generateKSUID()
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// ExpireRemove to expire the remove in a environment
func (environment *Environment) ExpireRemove(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Model(&env).Update("remove_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// DebugHTTP to check if the environment has enabled debugging for HTTP
func (environment *Environment) DebugHTTP(name string) bool {
	env, err := environment.Get(name)
	if err != nil {
		return false
	}
	return env.DebugHTTP
}

// ChangeDebugHTTP to change the value of DebugHTTP for a environment
func (environment *Environment) ChangeDebugHTTP(name string, value bool) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	if err := environment.DB.Model(&env).Updates(map[string]interface{}{"debug_http": value}).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}
