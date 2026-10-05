package users

import (
	"context"
	"sync"
)

type permissionContextKey struct{}

// permissionCache lives for one request (or one stream authorization pass).
// Never share it between requests: the database remains authoritative for
// revocation, including changes made by another API replica or the CLI.
type permissionCache struct {
	mu          sync.Mutex
	users       map[string]AdminUser
	permissions map[string]map[string][]UserPermission
}

// WithPermissionCache starts a fresh, empty authorization snapshot.
func WithPermissionCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, permissionContextKey{}, &permissionCache{
		users:       make(map[string]AdminUser),
		permissions: make(map[string]map[string][]UserPermission),
	})
}

// CacheAuthenticatedUser reuses the row just checked by token authentication.
// Call only after validating the stored token, with a fresh request cache.
func CacheAuthenticatedUser(ctx context.Context, user AdminUser) {
	if cache, ok := ctx.Value(permissionContextKey{}).(*permissionCache); ok {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		cache.users[user.Username] = user
	}
}

// CheckPermissionsContext caches user and environment permission rows only
// within the supplied request. Without a cache it uses the authoritative
// CheckPermissions path, as do callers outside HTTP handlers.
func (m *UserManager) CheckPermissionsContext(ctx context.Context, username string, level AccessLevel, environment string) bool {
	cache, ok := ctx.Value(permissionContextKey{}).(*permissionCache)
	if !ok {
		return m.CheckPermissions(username, level, environment)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	user, found := cache.users[username]
	if !found {
		if err := m.DB.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
			return false
		}
		cache.users[username] = user
	}
	if user.Admin || (environment == NoEnvironment && level == UserLevel) {
		return true
	}
	byEnvironment := cache.permissions[username]
	if byEnvironment == nil {
		byEnvironment = make(map[string][]UserPermission)
		cache.permissions[username] = byEnvironment
	}
	perms, found := byEnvironment[environment]
	if !found {
		if err := m.DB.WithContext(ctx).Where("username = ? AND environment = ?", username, environment).Find(&perms).Error; err != nil {
			return false
		}
		byEnvironment[environment] = perms
	}
	return permissionsAllow(perms, level)
}

func permissionsAllow(perms []UserPermission, level AccessLevel) bool {
	for _, p := range perms {
		if p.AccessType == int(AdminLevel) && p.AccessValue {
			return true
		}
		if p.AccessType == int(level) {
			return p.AccessValue
		}
	}
	return false
}
