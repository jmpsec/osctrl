package environments

import (
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	// DefaultEnrollPath as default value for enrolling nodes
	DefaultEnrollPath string = settings.ScriptEnroll
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
	// DefaultFlagsPath
	DefaultFlagsPath string = "osctrld-flags"
	// DefaultCertPath
	DefaultCertPath string = "osctrld-cert"
	// DefaultVerifyPath
	DefaultVerifyPath string = "osctrld-verify"
	// DefaultScriptPath
	DefaultScriptPath string = "osctrld-script"
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
	DebPackage       string
	RpmPackage       string
	MsiPackage       string
	PkgPackage       string
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
	AcceptEnrolls    bool
	UserID           uint
}

// MapEnvironments to hold the TLS environments by name and UUID
type MapEnvironments map[string]TLSEnvironment

// NameUUID to just hold the environment name and UUID
type NameUUID struct {
	Name string
	UUID string
	ID   uint
}

// MapEnvByID to hold the environments name and UUID by ID
type MapEnvByID map[uint]NameUUID

// MapEnvByString to hold the environments name and UUID by string
type MapEnvByString map[string]NameUUID

// Environment keeps all TLS Environments
type Environment struct {
	DB *gorm.DB
}

// CreateEnvironment to initialize the environment struct and tables
func CreateEnvironment(backend *gorm.DB) *Environment {
	var e *Environment
	e = &Environment{DB: backend}
	// table tls_environments
	if err := backend.AutoMigrate(&TLSEnvironment{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (tls_environments): %v", err)
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

// Get TLS Environment by UUID
func (environment *Environment) GetByUUID(uuid string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("uuid = ?", uuid).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Get TLS Environment by Name
func (environment *Environment) GetByName(name string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("name = ?", name).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Get TLS Environment by ID
func (environment *Environment) GetByID(id uint) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("ID = ?", id).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Empty generates an empty TLSEnvironment with default values
func (environment *Environment) Empty(name, hostname string) TLSEnvironment {
	return TLSEnvironment{
		UUID:             utils.GenUUID(),
		Name:             name,
		Hostname:         hostname,
		Secret:           utils.GenRandomString(DefaultSecretLength),
		EnrollSecretPath: utils.GenKSUID(),
		RemoveSecretPath: utils.GenKSUID(),
		EnrollExpire:     time.Now(),
		RemoveExpire:     time.Now(),
		DebPackage:       "",
		RpmPackage:       "",
		MsiPackage:       "",
		PkgPackage:       "",
		Type:             DefaultEnvironmentType,
		DebugHTTP:        false,
		Icon:             DefaultEnvironmentIcon,
		Flags:            "{}",
		Options:          "{}",
		Schedule:         "{}",
		Packs:            "{}",
		Decorators:       "{}",
		ATC:              "{}",
		Configuration:    "{}",
		Certificate:      "",
		ConfigTLS:        true,
		ConfigInterval:   DefaultConfigInterval,
		LoggingTLS:       true,
		LogInterval:      DefaultLogInterval,
		QueryTLS:         true,
		CarvesTLS:        true,
		QueryInterval:    DefaultQueryInterval,
		EnrollPath:       DefaultEnrollPath,
		AcceptEnrolls:    true,
		LogPath:          DefaultLogPath,
		ConfigPath:       DefaultConfigPath,
		QueryReadPath:    DefaultQueryReadPath,
		QueryWritePath:   DefaultQueryWritePath,
		CarverInitPath:   DefaultCarverInitPath,
		CarverBlockPath:  DefaultCarverBlockPath,
	}
}

// Create new TLS Environment
func (environment *Environment) Create(env *TLSEnvironment) error {
	if err := environment.DB.Create(&env).Error; err != nil {
		return fmt.Errorf("Create TLS Environment %v", err)
	}
	return nil
}

// Exists checks if TLS Environment exists already
func (environment *Environment) Exists(identifier string) bool {
	var results int64
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

// GetMapByID returns a smaller map of environments by ID
func (environment *Environment) GetMapByID() (MapEnvByID, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %v", err)
	}
	_map := make(MapEnvByID)
	for _, e := range all {
		_n := NameUUID{
			Name: e.Name,
			UUID: e.UUID,
			ID:   e.ID,
		}
		_map[e.ID] = _n
	}
	return _map, nil
}

// GetMapByString returns a smaller map of environments by string (name and UUID)
func (environment *Environment) GetMapByString() (MapEnvByString, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %v", err)
	}
	_map := make(MapEnvByString)
	for _, e := range all {
		_n := NameUUID{
			Name: e.Name,
			UUID: e.UUID,
			ID:   e.ID,
		}
		_map[e.Name] = _n
		_map[e.UUID] = _n
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
func (environment *Environment) UpdateOptions(idEnv, options string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("options", options).Error; err != nil {
		return fmt.Errorf("Update options %v", err)
	}
	return nil
}

// UpdateSchedule to update schedule for an environment
func (environment *Environment) UpdateSchedule(idEnv, schedule string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("schedule", schedule).Error; err != nil {
		return fmt.Errorf("Update schedule %v", err)
	}
	return nil
}

// UpdatePacks to update packs for an environment
func (environment *Environment) UpdatePacks(idEnv, packs string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("packs", packs).Error; err != nil {
		return fmt.Errorf("Update packs %v", err)
	}
	return nil
}

// UpdateDecorators to update decorators for an environment
func (environment *Environment) UpdateDecorators(idEnv, decorators string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("decorators", decorators).Error; err != nil {
		return fmt.Errorf("Update decorators %v", err)
	}
	return nil
}

// UpdateATC to update ATC for an environment
func (environment *Environment) UpdateATC(idEnv, atc string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("atc", atc).Error; err != nil {
		return fmt.Errorf("Update ATC %v", err)
	}
	return nil
}

// UpdateCertificate to update decorators for an environment
func (environment *Environment) UpdateCertificate(idEnv, certificate string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("certificate", certificate).Error; err != nil {
		return fmt.Errorf("UpdateUpdateCertificate %v", err)
	}
	return nil
}

// UpdateDebPackage to update DEB package for an environment
func (environment *Environment) UpdateDebPackage(idEnv, debpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("deb_package", debpackage).Error; err != nil {
		return fmt.Errorf("UpdateDebPackage %v", err)
	}
	return nil
}

// UpdateRpmPackage to update RPM package for an environment
func (environment *Environment) UpdateRpmPackage(idEnv, rpmpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("rpm_package", rpmpackage).Error; err != nil {
		return fmt.Errorf("UpdateRpmPackage %v", err)
	}
	return nil
}

// UpdateMsiPackage to update MSI package for an environment
func (environment *Environment) UpdateMsiPackage(idEnv, msipackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("msi_package", msipackage).Error; err != nil {
		return fmt.Errorf("UpdateMsiPackage %v", err)
	}
	return nil
}

// UpdatePkgPackage to update PKG package for an environment
func (environment *Environment) UpdatePkgPackage(idEnv, pkgpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("pkg_package", pkgpackage).Error; err != nil {
		return fmt.Errorf("UpdatePkgPackage %v", err)
	}
	return nil
}

// UpdateFlags to update flags for an environment
func (environment *Environment) UpdateFlags(idEnv, flags string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("flags", flags).Error; err != nil {
		return fmt.Errorf("Update flags %v", err)
	}
	return nil
}

// UpdateHostname to update hostname for an environment
func (environment *Environment) UpdateHostname(idEnv, hostname string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("hostname", hostname).Error; err != nil {
		return fmt.Errorf("Update hostname %v", err)
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
		return fmt.Errorf("UpdatesUpdateIntervals %v", err)
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
	rotated.Secret = utils.GenRandomString(DefaultSecretLength)
	rotated.EnrollSecretPath = utils.GenKSUID()
	rotated.RemoveSecretPath = utils.GenKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateSecrets %v", err)
	}
	return nil
}

// RotateEnrollPath to replace SecretPath for enrolling in an environment
func (environment *Environment) RotateEnroll(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	rotated := env
	rotated.EnrollSecretPath = utils.GenKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateEnrollPath %v", err)
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
	rotated.Secret = utils.GenRandomString(DefaultSecretLength)
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateSecret %v", err)
	}
	return nil
}

// ExpireEnroll to expire the enroll in an environment
func (environment *Environment) ExpireEnroll(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("UpdateExpireEnroll %v", err)
	}
	return nil
}

// ExtendEnroll to extend the enroll in an environment
func (environment *Environment) ExtendEnroll(idEnv string) error {
	extended := time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", extended).Error; err != nil {
		return fmt.Errorf("UpdateExtendEnroll %v", err)
	}
	return nil
}

// NotExpireEnroll to mark the enroll in an environment as not expiring
func (environment *Environment) NotExpireEnroll(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", time.Time{}).Error; err != nil {
		return fmt.Errorf("NotExpireEnroll %v", err)
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
	rotated.RemoveSecretPath = utils.GenKSUID()
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateRemove %v", err)
	}
	return nil
}

// ExpireRemove to expire the remove in an environment
func (environment *Environment) ExpireRemove(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("remove_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("UpdateExpireRemove %v", err)
	}
	return nil
}

// ExtendRemove to extend the remove in an environment
func (environment *Environment) ExtendRemove(idEnv string) error {
	env, err := environment.Get(idEnv)
	if err != nil {
		return fmt.Errorf("error getting environment %v", err)
	}
	extended := env.RemoveExpire.Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Update("remove_expire", extended).Error; err != nil {
		return fmt.Errorf("UpdateExtendRemove %v", err)
	}
	return nil
}

// NotExpireRemove to mark the remove in an environment as not expiring
func (environment *Environment) NotExpireRemove(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("remove_expire", time.Time{}).Error; err != nil {
		return fmt.Errorf("NotExpireRemove %v", err)
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
func (environment *Environment) ChangeDebugHTTP(idEnv string, value bool) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Updates(map[string]interface{}{"debug_http": value}).Error; err != nil {
		return fmt.Errorf("UpdatesChangeDebugHTTP %v", err)
	}
	return nil
}
