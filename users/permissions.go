package users

import (
	"encoding/json"
	"fmt"
	"log"
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
	// UserLevel for regula user privileges
	UserLevel
	// NoEnvironment to be explicit when used
	NoEnvironment = ""
)

// GenPermissions to generate the struct with empty permissions
func (m *UserManager) GenPermissions(environments []string, level AccessLevel) UserPermissions {
	envs := make(EnvPermissions)
	for _, e := range environments {
		envs[e] = true
	}
	perms := UserPermissions{
		Environments: envs,
		Query:        (level == QueryLevel || level == AdminLevel),
		Carve:        (level == CarveLevel || level == AdminLevel),
	}
	return perms
}

// CheckPermissions to verify access for a username
func (m *UserManager) CheckPermissions(username string, level AccessLevel, environment string) bool {
	exist, user := m.ExistsGet(username)
	if !exist {
		log.Printf("user %s does not exist", username)
		return false
	}
	// Admin has the highest level of access
	if user.Admin {
		return true
	}
	perms, err := m.ConvertPermissions(user.Permissions.RawMessage)
	if err != nil {
		log.Printf("error converting permissions %v", err)
		return false
	}
	switch level {
	case QueryLevel:
		return perms.Query
	case CarveLevel:
		return perms.Carve
	case EnvLevel:
		return perms.Environments[environment]
	case UserLevel:
		return true
	}
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
