package environments

import (
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
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

// EnvManager keeps all TLS Environments
type EnvManager struct {
	DB *gorm.DB
}

// CreateEnvironment to initialize the environment struct and tables
func CreateEnvironment(backend *gorm.DB) *EnvManager {
	e := &EnvManager{DB: backend}
	// table tls_environments
	if err := backend.AutoMigrate(&TLSEnvironment{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (tls_environments): %v", err)
	}
	return e
}

// Get TLS Environment by name or UUID
func (environment *EnvManager) Get(identifier string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("name = ? OR uuid = ?", identifier, identifier).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Get TLS Environment by UUID
func (environment *EnvManager) GetByUUID(uuid string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("uuid = ?", uuid).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Get TLS Environment by Name
func (environment *EnvManager) GetByName(name string) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("name = ?", name).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Get TLS Environment by ID
func (environment *EnvManager) GetByID(id uint) (TLSEnvironment, error) {
	var env TLSEnvironment
	if err := environment.DB.Where("ID = ?", id).First(&env).Error; err != nil {
		return env, err
	}
	return env, nil
}

// Empty generates an empty TLSEnvironment with default values
func (environment *EnvManager) Empty(name, hostname string) TLSEnvironment {
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
func (environment *EnvManager) Create(env *TLSEnvironment) error {
	if err := environment.DB.Create(&env).Error; err != nil {
		return fmt.Errorf("Create TLS Environment %w", err)
	}
	return nil
}

// Exists checks if TLS Environment exists already
func (environment *EnvManager) Exists(identifier string) bool {
	var results int64
	environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", identifier, identifier).Count(&results)
	return (results > 0)
}

// ExistsGet checks if TLS Environment exists already and returns it
func (environment *EnvManager) ExistsGet(identifier string) (bool, TLSEnvironment) {
	e, err := environment.Get(identifier)
	if err != nil {
		return false, TLSEnvironment{}
	}
	return true, e
}

// All gets all TLS Environment
func (environment *EnvManager) All() ([]TLSEnvironment, error) {
	var envs []TLSEnvironment
	if err := environment.DB.Find(&envs).Error; err != nil {
		return envs, err
	}
	return envs, nil
}

// Names gets just all TLS Environment names
func (environment *EnvManager) Names() ([]string, error) {
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
func (environment *EnvManager) UUIDs() ([]string, error) {
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
func (environment *EnvManager) GetMap() (MapEnvironments, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %w", err)
	}
	_map := make(MapEnvironments)
	for _, e := range all {
		_map[e.Name] = e
		_map[e.UUID] = e
	}
	return _map, nil
}

// GetMapByID returns a smaller map of environments by ID
func (environment *EnvManager) GetMapByID() (MapEnvByID, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %w", err)
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
func (environment *EnvManager) GetMapByString() (MapEnvByString, error) {
	all, err := environment.All()
	if err != nil {
		return nil, fmt.Errorf("error getting environments %w", err)
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
func (environment *EnvManager) Delete(identifier string) error {
	env, err := environment.Get(identifier)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	if err := environment.DB.Unscoped().Delete(&env).Error; err != nil {
		return fmt.Errorf("delete %w", err)
	}
	return nil
}

// Update TLS Environment
func (environment *EnvManager) Update(e TLSEnvironment) error {
	env, err := environment.Get(e.Name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	if err := environment.DB.Model(&env).Updates(e).Error; err != nil {
		return fmt.Errorf("updates %w", err)
	}
	return nil
}

// UpdateOptions to update options for an environment
func (environment *EnvManager) UpdateOptions(idEnv, options string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("options", options).Error; err != nil {
		return fmt.Errorf("Update options %w", err)
	}
	return nil
}

// UpdateSchedule to update schedule for an environment
func (environment *EnvManager) UpdateSchedule(idEnv, schedule string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("schedule", schedule).Error; err != nil {
		return fmt.Errorf("Update schedule %w", err)
	}
	return nil
}

// UpdatePacks to update packs for an environment
func (environment *EnvManager) UpdatePacks(idEnv, packs string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("packs", packs).Error; err != nil {
		return fmt.Errorf("Update packs %w", err)
	}
	return nil
}

// UpdateDecorators to update decorators for an environment
func (environment *EnvManager) UpdateDecorators(idEnv, decorators string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("decorators", decorators).Error; err != nil {
		return fmt.Errorf("Update decorators %w", err)
	}
	return nil
}

// UpdateATC to update ATC for an environment
func (environment *EnvManager) UpdateATC(idEnv, atc string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("atc", atc).Error; err != nil {
		return fmt.Errorf("Update ATC %w", err)
	}
	return nil
}

// UpdateCertificate to update decorators for an environment
func (environment *EnvManager) UpdateCertificate(idEnv, certificate string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("certificate", certificate).Error; err != nil {
		return fmt.Errorf("UpdateUpdateCertificate %w", err)
	}
	return nil
}

// UpdateDebPackage to update DEB package for an environment
func (environment *EnvManager) UpdateDebPackage(idEnv, debpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("deb_package", debpackage).Error; err != nil {
		return fmt.Errorf("UpdateDebPackage %w", err)
	}
	return nil
}

// UpdateRpmPackage to update RPM package for an environment
func (environment *EnvManager) UpdateRpmPackage(idEnv, rpmpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("rpm_package", rpmpackage).Error; err != nil {
		return fmt.Errorf("UpdateRpmPackage %w", err)
	}
	return nil
}

// UpdateMsiPackage to update MSI package for an environment
func (environment *EnvManager) UpdateMsiPackage(idEnv, msipackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("msi_package", msipackage).Error; err != nil {
		return fmt.Errorf("UpdateMsiPackage %w", err)
	}
	return nil
}

// UpdatePkgPackage to update PKG package for an environment
func (environment *EnvManager) UpdatePkgPackage(idEnv, pkgpackage string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("pkg_package", pkgpackage).Error; err != nil {
		return fmt.Errorf("UpdatePkgPackage %w", err)
	}
	return nil
}

// UpdateFlags to update flags for an environment
func (environment *EnvManager) UpdateFlags(idEnv, flags string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("flags", flags).Error; err != nil {
		return fmt.Errorf("Update flags %w", err)
	}
	return nil
}

// UpdateHostname to update hostname for an environment
func (environment *EnvManager) UpdateHostname(idEnv, hostname string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("hostname", hostname).Error; err != nil {
		return fmt.Errorf("Update hostname %w", err)
	}
	return nil
}

// UpdateIntervals to update intervals for an environment
func (environment *EnvManager) UpdateIntervals(name string, csecs, lsecs, qsecs int) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	updated := env
	updated.ConfigInterval = csecs
	updated.LogInterval = lsecs
	updated.QueryInterval = qsecs
	if err := environment.DB.Model(&env).Updates(updated).Error; err != nil {
		return fmt.Errorf("UpdatesUpdateIntervals %w", err)
	}
	return nil
}

// RotateSecrets to replace Secret and SecretPath for an environment
func (environment *EnvManager) RotateSecrets(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	rotated := env
	rotated.Secret = utils.GenRandomString(DefaultSecretLength)
	rotated.EnrollSecretPath = utils.GenKSUID()
	rotated.RemoveSecretPath = utils.GenKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateSecrets %w", err)
	}
	return nil
}

// RotateEnrollPath to replace SecretPath for enrolling in an environment
func (environment *EnvManager) RotateEnroll(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	rotated := env
	rotated.EnrollSecretPath = utils.GenKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateEnrollPath %w", err)
	}
	return nil
}

// RotateSecret to replace the current Secret for an environment
func (environment *EnvManager) RotateSecret(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	rotated := env
	rotated.Secret = utils.GenRandomString(DefaultSecretLength)
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateSecret %w", err)
	}
	return nil
}

// ExpireEnroll to expire the enroll in an environment
func (environment *EnvManager) ExpireEnroll(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("UpdateExpireEnroll %w", err)
	}
	return nil
}

// ExtendEnroll to extend the enroll in an environment
func (environment *EnvManager) ExtendEnroll(idEnv string) error {
	extended := time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", extended).Error; err != nil {
		return fmt.Errorf("UpdateExtendEnroll %w", err)
	}
	return nil
}

// NotExpireEnroll to mark the enroll in an environment as not expiring
func (environment *EnvManager) NotExpireEnroll(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("enroll_expire", time.Time{}).Error; err != nil {
		return fmt.Errorf("NotExpireEnroll %w", err)
	}
	return nil
}

// RotateRemove to replace Secret and SecretPath for enrolling in an environment
func (environment *EnvManager) RotateRemove(name string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	rotated := env
	rotated.RemoveSecretPath = utils.GenKSUID()
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Updates(rotated).Error; err != nil {
		return fmt.Errorf("UpdatesRotateRemove %w", err)
	}
	return nil
}

// ExpireRemove to expire the remove in an environment
func (environment *EnvManager) ExpireRemove(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("remove_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("UpdateExpireRemove %w", err)
	}
	return nil
}

// ExtendRemove to extend the remove in an environment
func (environment *EnvManager) ExtendRemove(idEnv string) error {
	env, err := environment.Get(idEnv)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	extended := env.RemoveExpire.Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := environment.DB.Model(&env).Update("remove_expire", extended).Error; err != nil {
		return fmt.Errorf("UpdateExtendRemove %w", err)
	}
	return nil
}

// NotExpireRemove to mark the remove in an environment as not expiring
func (environment *EnvManager) NotExpireRemove(idEnv string) error {
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("remove_expire", time.Time{}).Error; err != nil {
		return fmt.Errorf("NotExpireRemove %w", err)
	}
	return nil
}
