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
	scopeTags   map[string][]uint
}

// WithPermissionCache starts a fresh, empty authorization snapshot.
func WithPermissionCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, permissionContextKey{}, &permissionCache{
		users:       make(map[string]AdminUser),
		permissions: make(map[string]map[string][]UserPermission),
		scopeTags:   make(map[string][]uint),
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
	cache, hasCache := ctx.Value(permissionContextKey{}).(*permissionCache)
	if !hasCache {
		return m.CheckPermissions(username, level, environment)
	}
	user, ok := m.cachedUser(ctx, username)
	if !ok {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if user.Admin || (environment == NoEnvironment && level == UserLevel) {
		return true
	}
	// Global gates are decided by the Admin flag alone; see CheckPermissions.
	if environment == NoEnvironment {
		return false
	}
	perms, ok := m.cachedEnvPermissions(ctx, cache, username, environment)
	if !ok {
		return false
	}
	if level == UserLevel && user.HasRole(RoleReadOnly) {
		return true
	}
	return permissionsAllow(perms, level)
}

// cachedEnvPermissions loads the env's rows through the request cache.
// The caller must hold cache.mu.
func (m *UserManager) cachedEnvPermissions(ctx context.Context, cache *permissionCache, username, environment string) ([]UserPermission, bool) {
	byEnvironment := cache.permissions[username]
	if byEnvironment == nil {
		byEnvironment = make(map[string][]UserPermission)
		cache.permissions[username] = byEnvironment
	}
	perms, found := byEnvironment[environment]
	if !found {
		if err := m.DB.WithContext(ctx).Where("username = ? AND environment = ?", username, environment).Find(&perms).Error; err != nil {
			return nil, false
		}
		byEnvironment[environment] = perms
	}
	return perms, true
}

// cachedUser returns the user from the request cache, loading it from the
// database on a miss. Without a cache it reads the database directly.
func (m *UserManager) cachedUser(ctx context.Context, username string) (AdminUser, bool) {
	cache, ok := ctx.Value(permissionContextKey{}).(*permissionCache)
	if !ok {
		user, err := m.Get(username)
		return user, err == nil
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if user, found := cache.users[username]; found {
		return user, true
	}
	var user AdminUser
	if err := m.DB.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return user, false
	}
	cache.users[username] = user
	return user, true
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
