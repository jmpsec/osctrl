package users

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// UserAccess to provide an abstraction for user access between environment and permissions
type UserAccess map[string]EnvAccess

// UserPermissions to abstract the permissions for a user
type EnvAccess struct {
	User  bool `json:"user"`
	Query bool `json:"query"`
	Carve bool `json:"carve"`
	Admin bool `json:"admin"`
}

// UserPermission to hold all permissions for users
type UserPermission struct {
	gorm.Model
	Username      string `gorm:"index"`
	AccessType    int
	AccessValue   bool
	Environment   string
	EnvironmentID uint
	GrantedBy     string
}

// AccessLevel as abstraction of level of access for a user
type AccessLevel int

const (
	// AdminLevel for admin privileges
	AdminLevel AccessLevel = iota
	// QueryLevel for query privileges
	QueryLevel
	// CarveLevel for carve privileges
	CarveLevel
	// UserLevel for regular user privileges
	UserLevel
	// NoEnvironment to be explicit when used
	NoEnvironment = ""
)

// CreatePermission new permission
func (m *UserManager) CreatePermission(permission UserPermission) error {
	if err := m.DB.Create(&permission).Error; err != nil {
		return fmt.Errorf("Create UserPermission %v", err)
	}
	return nil
}

// ResetAccess to

// CreatePermissions to iterate through a slice of permissions
func (m *UserManager) CreatePermissions(permissions []UserPermission) error {
	for _, p := range permissions {
		if err := m.CreatePermission(p); err != nil {
			return err
		}
	}
	return nil
}

// GenEnvUserAccess to generate the struct with empty access
func (m *UserManager) GenEnvUserAccess(envs []string, user, query, carve, admin bool) UserAccess {
	access := make(UserAccess)
	for _, e := range envs {
		access[e] = EnvAccess{
			User:  user,
			Query: query,
			Carve: carve,
			Admin: admin,
		}
	}
	return access
}

// GenUserAccess to generate the struct with empty access
func (m *UserManager) GenUserAccess(env environments.TLSEnvironment, envAccess EnvAccess) UserAccess {
	access := make(UserAccess)
	access[env.UUID] = envAccess
	return access
}

// GenUserPermission Helper to generate struct
func (m *UserManager) GenUserPermission(username, granted, env string, aType int, aValue bool) UserPermission {
	return UserPermission{
		Username:    username,
		AccessType:  aType,
		AccessValue: aValue,
		Environment: env,
		GrantedBy:   granted,
	}
}

// GenPermission to generate the struct with empty permissions
// FIXME this probably can be implemented in a better way
func (m *UserManager) GenPermissions(username, granted string, access UserAccess) []UserPermission {
	var res []UserPermission
	for env, a := range access {
		var p UserPermission
		// User
		p = m.GenUserPermission(username, granted, env, int(UserLevel), a.User)
		res = append(res, p)
		// Admin
		p = m.GenUserPermission(username, granted, env, int(AdminLevel), a.Admin)
		res = append(res, p)
		// Query
		p = m.GenUserPermission(username, granted, env, int(QueryLevel), a.Query)
		res = append(res, p)
		// Carve
		p = m.GenUserPermission(username, granted, env, int(CarveLevel), a.Carve)
		res = append(res, p)
	}
	return res
}

// CheckPermissions to verify access for a username
func (m *UserManager) CheckPermissions(username string, level AccessLevel, environment string) bool {
	exist, user := m.ExistsGet(username)
	if !exist {
		log.Info().Msgf("user %s does not exist", username)
		return false
	}
	// If user is an admin, access is yes
	if user.Admin {
		return true
	}
	// If environment is not set, access is granted based on access level
	if (environment == NoEnvironment) && (level == UserLevel) {
		return true
	}
	// Check if the user has access to the environment
	var perms []UserPermission
	if err := m.DB.Where("username = ? AND environment = ?", username, environment).Find(&perms).Error; err != nil {
		return false
	}
	for _, p := range perms {
		// Access is yes for admins
		if p.AccessType == int(AdminLevel) && p.AccessValue {
			return true
		}
		if p.AccessType == int(level) {
			return p.AccessValue
		}
	}
	return false
}

// ChangePermissions for setting user permissions by username
func (m *UserManager) ChangePermissions(username, environment string, permissions []UserPermission) error {
	for _, p := range permissions {
		if err := m.ChangePermission(username, environment, p); err != nil {
			return err
		}
	}
	return nil
}

// ChangePermissions for setting user permissions by username
func (m *UserManager) ChangePermission(username, environment string, perm UserPermission) error {
	if !m.Exists(username) {
		return fmt.Errorf("user %s does not exist", username)
	}
	if perm.Username != username || perm.Environment != environment {
		return fmt.Errorf("username/environment mismatch [%s/%s]", username, environment)
	}
	m.DB.Model(&perm).Updates(map[string]interface{}{
		"access_type":  perm.AccessType,
		"access_value": perm.AccessValue,
		"granted_by":   perm.GrantedBy,
	})
	return nil
}

// ChangeAccess for setting user access by username and environment
func (m *UserManager) ChangeAccess(username, environment string, access EnvAccess) error {
	if !m.Exists(username) {
		return fmt.Errorf("user %s does not exist", username)
	}
	if err := m.SetEnvUser(username, environment, access.User); err != nil {
		return fmt.Errorf("error setting user access - %s", err)
	}
	if err := m.SetEnvQuery(username, environment, access.Query); err != nil {
		return fmt.Errorf("error setting query access - %s", err)
	}
	if err := m.SetEnvCarve(username, environment, access.Carve); err != nil {
		return fmt.Errorf("error setting carve access - %s", err)
	}
	if err := m.SetEnvAdmin(username, environment, access.Admin); err != nil {
		return fmt.Errorf("error setting admin access - %s", err)
	}
	return nil
}

// SetEnvUser to change the user access for a user and environment
func (m *UserManager) SetEnvUser(username, environment string, user bool) error {
	return m.SetEnvLevel(username, environment, UserLevel, user)
}

// SetEnvQuery to change the query access for a user and environment
func (m *UserManager) SetEnvQuery(username, environment string, query bool) error {
	return m.SetEnvLevel(username, environment, QueryLevel, query)
}

// SetEnvCarve to change the carve access for a user and environment
func (m *UserManager) SetEnvCarve(username, environment string, carve bool) error {
	return m.SetEnvLevel(username, environment, CarveLevel, carve)
}

// SetEnvAdmin to change the admin access for a user and environment
func (m *UserManager) SetEnvAdmin(username, environment string, admin bool) error {
	return m.SetEnvLevel(username, environment, AdminLevel, admin)
}

// SetEnvLevel to change the access for a user
func (m *UserManager) SetEnvLevel(username, environment string, level AccessLevel, value bool) error {
	perm, err := m.GetPermission(username, environment, level)
	if err != nil {
		return fmt.Errorf("error getting permissions for %s/%s - %s", username, environment, err)
	}
	m.DB.Model(&perm).Updates(map[string]interface{}{
		"access_type":  level,
		"access_value": value,
		"granted_by":   perm.GrantedBy,
	})
	return nil
}

// GetAccess to extract all access by username
func (m *UserManager) GetAccess(username string) (UserAccess, error) {
	access := make(UserAccess)
	if !m.Exists(username) {
		return access, fmt.Errorf("user %s does not exist", username)
	}
	var perms []UserPermission
	if err := m.DB.Where("username = ?", username).Find(&perms).Error; err != nil {
		return access, err
	}
	for _, p := range perms {
		acs := access[p.Environment]
		switch p.AccessType {
		case int(UserLevel):
			acs.User = p.AccessValue
		case int(QueryLevel):
			acs.Query = p.AccessValue
		case int(CarveLevel):
			acs.Carve = p.AccessValue
		case int(AdminLevel):
			acs.Admin = p.AccessValue
		}
		access[p.Environment] = acs
	}
	return access, nil
}

// GetEnvAccess to get the access for a user and a specific environment
func (m *UserManager) GetEnvAccess(username, env string) (EnvAccess, error) {
	var envAccess EnvAccess
	perms, err := m.GetEnvPermissions(username, env)
	if len(perms) == 0 {
		return envAccess, fmt.Errorf("record not found")
	}
	if err != nil {
		return envAccess, fmt.Errorf("error getting permissions - %s", err)
	}
	for _, p := range perms {
		switch p.AccessType {
		case int(UserLevel):
			envAccess.User = p.AccessValue
		case int(QueryLevel):
			envAccess.Query = p.AccessValue
		case int(CarveLevel):
			envAccess.Carve = p.AccessValue
		case int(AdminLevel):
			envAccess.Admin = p.AccessValue
		}
	}
	return envAccess, nil
}

// GetPermission to extract permission by username and environment
func (m *UserManager) GetPermission(username, environment string, aType AccessLevel) (UserPermission, error) {
	var perm UserPermission
	if !m.Exists(username) {
		return perm, fmt.Errorf("user %s does not exist", username)
	}
	if err := m.DB.Where("username = ? AND environment = ? AND access_type = ?", username, environment, aType).First(&perm).Error; err != nil {
		return perm, err
	}
	return perm, nil
}

// GetPermissions to extract permissions by username and environment
func (m *UserManager) GetEnvPermissions(username, environment string) ([]UserPermission, error) {
	var perms []UserPermission
	if !m.Exists(username) {
		return perms, fmt.Errorf("user %s does not exist", username)
	}
	if err := m.DB.Where("username = ? AND environment = ?", username, environment).Find(&perms).Error; err != nil {
		return perms, err
	}
	return perms, nil
}

// GetAllPermissions to extract permissions by username
func (m *UserManager) GetAllPermissions(username string) ([]UserPermission, error) {
	var perms []UserPermission
	if !m.Exists(username) {
		return perms, fmt.Errorf("user %s does not exist", username)
	}
	if err := m.DB.Where("username = ?", username).Find(&perms).Error; err != nil {
		return perms, err
	}
	return perms, nil
}

// DeleteEnvPermissions to delete all permissions by username and environment
func (m *UserManager) DeleteEnvPermissions(username, environment string) error {
	if !m.Exists(username) {
		return fmt.Errorf("user %s does not exist", username)
	}
	perms, err := m.GetEnvPermissions(username, environment)
	if err != nil {
		return fmt.Errorf("error getting permissions for %s/%s", username, environment)
	}
	for _, p := range perms {
		if err := m.DB.Unscoped().Delete(&p).Error; err != nil {
			return fmt.Errorf("error deleting permission %v", err)
		}
	}
	return nil
}

// DeleteAllPermissions to delete all permissions by username
func (m *UserManager) DeleteAllPermissions(username string) error {
	if !m.Exists(username) {
		return fmt.Errorf("user %s does not exist", username)
	}
	perms, err := m.GetAllPermissions(username)
	if err != nil {
		return fmt.Errorf("error getting permissions for %s", username)
	}
	for _, p := range perms {
		if err := m.DB.Unscoped().Delete(&p).Error; err != nil {
			return fmt.Errorf("error deleting permission %v", err)
		}
	}
	return nil
}
