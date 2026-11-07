package users

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// GlobalRole is a capability that applies across all environments.
type GlobalRole int

const (
	RoleSuperuser GlobalRole = iota
	RoleUserManagement
	RoleEnvManagement
	RoleReadOnly
	RoleAlertAdmin
)

var (
	ErrSuperuserTarget  = errors.New("only a superuser can manage a superuser")
	ErrSuperuserGrant   = errors.New("only a superuser can grant superuser")
	ErrNoUserManagement = errors.New("user management role required")
)

// HasRole reports whether the user holds r. Superusers hold every role; user
// admins and environment managers also hold read-only. AlertAdmin does not
// imply read-only.
func (u AdminUser) HasRole(r GlobalRole) bool {
	if u.Admin {
		return true
	}
	switch r {
	case RoleUserManagement:
		return u.UserAdmin
	case RoleEnvManagement:
		return u.EnvManager
	case RoleReadOnly:
		return u.ReadOnlyAdmin || u.UserAdmin || u.EnvManager
	case RoleAlertAdmin:
		return u.AlertAdmin
	}
	return false
}

// HasRoleContext is HasRole for a username, using the request cache if any.
func (m *UserManager) HasRoleContext(ctx context.Context, username string, r GlobalRole) bool {
	user, ok := m.cachedUser(ctx, username)
	return ok && user.HasRole(r)
}

// RoleSet holds the roles to change; nil fields are left untouched.
type RoleSet struct {
	UserAdmin, EnvManager, ReadOnlyAdmin, AlertAdmin *bool
}

// SetRoles updates only the non-nil roles of an existing user.
func (m *UserManager) SetRoles(username string, roles RoleSet) error {
	if _, err := m.Get(username); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("user %s does not exist", username)
		}
		return fmt.Errorf("SetRoles lookup %w", err)
	}
	updates := map[string]any{}
	for col, v := range map[string]*bool{
		"user_admin": roles.UserAdmin, "env_manager": roles.EnvManager,
		"read_only_admin": roles.ReadOnlyAdmin, "alert_admin": roles.AlertAdmin,
	} {
		if v != nil {
			updates[col] = *v
		}
	}
	if len(updates) == 0 {
		return nil
	}
	if err := m.DB.Model(&AdminUser{}).Where("username = ?", username).Updates(updates).Error; err != nil {
		return fmt.Errorf("SetRoles %w", err)
	}
	return nil
}

// CheckManageUser keeps user admins away from superusers. A missing target
// (create flow) is treated as a plain user.
func (m *UserManager) CheckManageUser(ctx context.Context, actor, target string, grantsSuperuser bool) error {
	a, ok := m.cachedUser(ctx, actor)
	if !ok || !a.HasRole(RoleUserManagement) {
		return ErrNoUserManagement
	}
	if a.Admin {
		return nil
	}
	if grantsSuperuser {
		return ErrSuperuserGrant
	}
	t, err := m.Get(target)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil // create flow
	}
	if err != nil {
		return fmt.Errorf("CheckManageUser target lookup %w", err)
	}
	if t.Admin {
		return ErrSuperuserTarget
	}
	return nil
}
