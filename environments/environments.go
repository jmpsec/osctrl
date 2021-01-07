package environments

import (
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"
)

const (
	// DefaultEnrollPath as default value for enrolling nodes
	DefaultEnrollPath string = "enroll"
	// DefaultLogPath as default value for logging data from nodes
	DefaultLogPath string = "log"
	// DefaultLogInterval as default interval for logging data from nodes
	DefaultLogInterval int = 600
	// DefaultConfigPath as default value for configuring nodes
	DefaultConfigPath string = "config"
	// DefaultConfigInterval as default interval for configuring nodes
	DefaultConfigInterval int = 300
	// DefaultQueryReadPath as default value for distributing on-demand queries to nodes
	DefaultQueryReadPath string = "read"
	// DefaultQueryWritePath as default value for collecting results from on-demand queries
	DefaultQueryWritePath string = "write"
	// DefaultQueryInterval as default interval for distributing on-demand queries to nodes
	DefaultQueryInterval int = 60
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
	UUID             string `gorm:"index"`
	Name             string
	Hostname         string
	Secret           string
	EnrollSecretPath string
	EnrollExpire     time.Time
	RemoveSecretPath string
	RemoveExpire     time.Time
	Type             string
	DebugHTTP        bool
	Icon             string
	Options          string
	Schedule         string
	Packs            string
	Decorators       string
	ATC              string
	Configuration    string
	Flags            string
	Certificate      string
	ConfigTLS        bool
	ConfigInterval   int
	LoggingTLS       bool
	LogInterval      int
	QueryTLS         bool
	QueryInterval    int
	CarvesTLS        bool
	EnrollPath       string
	LogPath          string
	ConfigPath       string
	QueryReadPath    string
	QueryWritePath   string
	CarverInitPath   string
	CarverBlockPath  string
}

// MapEnvironments to hold the TLS environments by name and UUID
type MapEnvironments map[string]TLSEnvironment

// Environment keeps all TLS Environments
type Environment struct {
	DB *gorm.DB
}

// CreateEnvironment to initialize the environment struct and tables
func CreateEnvironment(backend *gorm.DB) *Environment {
	var e *Environment
	e = &Environment{DB: backend}
	// table tls_environments
	if err := backend.AutoMigrate(TLSEnvironment{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (tls_environments): %v", err)
	}
	return e
}

// Get TLS Environment by name or UUID
func (environment *Environment) Get(identifier string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("name = ? OR uuid = ?", identifier, identifier).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Empty generates an empty TLSEnvironment with default values
func (environment *Environment) Empty(name, hostname string) TLSEnvironment {
	return TLSEnvironment{
		UUID:             generateUUID(),
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
		Flags:            "",
		Options:          "",
		Schedule:         "",
		Packs:            "",
		Decorators:       "",
		ATC:              "",
		Configuration:    "",
		Certificate:      "",
		ConfigTLS:        true,
		ConfigInterval:   DefaultConfigInterval,
		LoggingTLS:       true,
		LogInterval:      DefaultLogInterval,
		QueryTLS:         true,
		CarvesTLS:        true,
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
func (environment *Environment) Exists(identifier string) bool {
	var results int
	environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", identifier, identifier).Count(&results)
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

// Names gets just all TLS Environment names
func (environment *Environment) Names() ([]string, error) {
	envs, err := environment.All()
	if err != nil {
		return []string{}, err
	}
	names := []string{}
	for _, e := range envs {
		names = append(names, e.Name)
	}
	return names, err
}

// UUIDs gets just all TLS Environment UUIDs
func (environment *Environment) UUIDs() ([]string, error) {
	envs, err := environment.All()
	if err != nil {
		return []string{}, err
	}
	uuids := []string{}
	for _, e := range envs {
		uuids = append(uuids, e.UUID)
	}
	return uuids, err
}

// GetMap returns the map of environments by name and UUID
func (environment *Environment) GetMap() (MapEnvironments, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %v", err)
	}
	_map := make(MapEnvironments)
	for _, e := range all {
		_map[e.Name] = e
		_map[e.UUID] = e
	}
	return _map, nil
}

// Delete TLS Environment by name or UUID
func (environment *Environment) Delete(identifier string) error {
	env, err := environment.Get(identifier)
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

// UpdateOptions to update options for an environment
func (environment *Environment) UpdateOptions(name, options string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("options", options).Error; err != nil {
		return fmt.Errorf("Update options %v", err)
	}
	return nil
}

// UpdateSchedule to update schedule for an environment
func (environment *Environment) UpdateSchedule(name, schedule string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("schedule", schedule).Error; err != nil {
		return fmt.Errorf("Update schedule %v", err)
	}
	return nil
}

// UpdatePacks to update packs for an environment
func (environment *Environment) UpdatePacks(name, packs string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("packs", packs).Error; err != nil {
		return fmt.Errorf("Update packs %v", err)
	}
	return nil
}

// UpdateDecorators to update decorators for an environment
func (environment *Environment) UpdateDecorators(name, decorators string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("decorators", decorators).Error; err != nil {
		return fmt.Errorf("Update decorators %v", err)
	}
	return nil
}

// UpdateATC to update ATC for an environment
func (environment *Environment) UpdateATC(name, atc string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("atc", atc).Error; err != nil {
		return fmt.Errorf("Update ATC %v", err)
	}
	return nil
}

// UpdateCertificate to update decorators for an environment
func (environment *Environment) UpdateCertificate(name, certificate string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("certificate", certificate).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// UpdateFlags to update flags for an environment
func (environment *Environment) UpdateFlags(name, flags string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("flags", flags).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// UpdateIntervals to update intervals for an environment
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

// RotateSecrets to replace Secret and SecretPath for an environment
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

// RotateEnrollPath to replace SecretPath for enrolling in an environment
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

// RotateSecret to replace the current Secret for an environment
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

// ExpireEnroll to expire the enroll in an environment
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

// RotateRemove to replace Secret and SecretPath for enrolling in an environment
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

// ExpireRemove to expire the remove in an environment
func (environment *Environment) ExpireRemove(name string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Update("remove_expire", time.Now()).Error; err != nil {
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

// ChangeDebugHTTP to change the value of DebugHTTP for an environment
func (environment *Environment) ChangeDebugHTTP(name string, value bool) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ?", name).Updates(map[string]interface{}{"debug_http": value}).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}
