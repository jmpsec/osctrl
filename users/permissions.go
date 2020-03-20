package users

import (
	"encoding/json"
	"fmt"
)

// EnvPermissions to hold permissions for environments
type EnvPermissions map[string]bool

// UserPermissions to abstract the permissions for a user
type UserPermissions struct {
	Environments EnvPermissions `json:"environments"`
	Query        bool           `json:"query"`
	Carve        bool           `json:"carve"`
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
	// EnvLevel for environment privileges
	EnvLevel
	// NoEnvironment to be explicit when used
	NoEnvironment = ""
)

// GenPermissions to generate the struct with empty permissions
func (m *UserManager) GenPermissions(environments []string, level bool) UserPermissions {
	envs := make(EnvPermissions)
	for _, e := range environments {
		envs[e] = level
	}
	perms := UserPermissions{
		Environments: envs,
		Query:        level,
		Carve:        level,
	}
	return perms
}

// CheckPermissions to verify access for a username
func (m *UserManager) CheckPermissions(username string, level AccessLevel, environment string) bool {

	return false
}

// GetPermissions to extract permissions by username
func (m *UserManager) GetPermissions(username string) (UserPermissions, error) {
	var perms UserPermissions
	user, err := m.Get(username)
	if err != nil {
		return perms, fmt.Errorf("error getting user %v", err)
	}
	if err := json.Unmarshal(user.Permissions.RawMessage, &perms); err != nil {
		return perms, fmt.Errorf("error parsing permissions %v", err)
	}
	return perms, nil
}

// ConvertPermissions to convert from stored Jsonb to struct
func (m *UserManager) ConvertPermissions(raw json.RawMessage) (UserPermissions, error) {
	var perms UserPermissions
	if err := json.Unmarshal(raw, &perms); err != nil {
		return perms, fmt.Errorf("error parsing permissions %v", err)
	}
	return perms, nil
}
