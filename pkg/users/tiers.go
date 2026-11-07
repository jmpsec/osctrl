package users

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Tier is the depth of query/carve access a user has in an environment.
type Tier int

const (
	TierNone Tier = iota
	TierTags
	TierStandard
	TierFull
)

var tierNames = [...]string{"none", "tags", "standard", "full"}

func (t Tier) String() string {
	if t < TierNone || int(t) >= len(tierNames) {
		return "none"
	}
	return tierNames[t]
}

// ParseTier converts a wire name to a Tier; empty and unknown names are errors.
func ParseTier(s string) (Tier, error) {
	for i, n := range tierNames {
		if n == s {
			return Tier(i), nil
		}
	}
	return TierNone, fmt.Errorf("invalid tier %q", s)
}

func noneIfEmpty(s string) string {
	if s == "" {
		return TierNone.String()
	}
	return s
}

// rowTier maps a stored Query/Carve row to its tier (0 on a granted row is
// standard, which is what every pre-tier row means).
func rowTier(p UserPermission) Tier {
	switch {
	case !p.AccessValue:
		return TierNone
	case p.Tier == 0:
		return TierStandard
	}
	return Tier(p.Tier)
}

// TierContext returns the user's tier for QueryLevel or CarveLevel in an
// environment, using the request cache when present.
func (m *UserManager) TierContext(ctx context.Context, username, envUUID string, level AccessLevel) Tier {
	user, ok := m.cachedUser(ctx, username)
	if !ok {
		return TierNone
	}
	if user.Admin {
		return TierFull
	}
	if envUUID == NoEnvironment {
		return TierNone
	}
	var perms []UserPermission
	if cache, hasCache := ctx.Value(permissionContextKey{}).(*permissionCache); hasCache {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if perms, ok = m.cachedEnvPermissions(ctx, cache, username, envUUID); !ok {
			return TierNone
		}
	} else if err := m.DB.WithContext(ctx).Where("username = ? AND environment = ?", username, envUUID).Find(&perms).Error; err != nil {
		return TierNone
	}
	t := TierNone
	for _, p := range perms {
		if p.AccessType == int(AdminLevel) && p.AccessValue {
			return TierFull
		}
		if p.AccessType == int(level) {
			t = rowTier(p)
		}
	}
	return t
}

// SetEnvTier stores a tier on the query or carve row, creating it if needed.
// TierNone writes AccessValue=false.
func (m *UserManager) SetEnvTier(username, environment string, level AccessLevel, t Tier) error {
	if environment == NoEnvironment {
		return errBlankPermissionEnv
	}
	if level != QueryLevel && level != CarveLevel {
		return fmt.Errorf("tiers apply only to query and carve levels")
	}
	if t < TierNone || t > TierFull {
		return fmt.Errorf("invalid tier %d", t)
	}
	granted := t != TierNone
	tier := 0
	if granted {
		tier = int(t)
	}
	perm, err := m.GetPermission(username, environment, level)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			row := UserPermission{Username: username, Environment: environment, AccessType: int(level), AccessValue: granted, Tier: tier}
			if cerr := m.DB.Create(&row).Error; cerr != nil {
				return fmt.Errorf("error creating permission row for %s/%s - %w", username, environment, cerr)
			}
			return nil
		}
		return fmt.Errorf("error getting permissions for %s/%s - %w", username, environment, err)
	}
	if err := m.DB.Model(&perm).Updates(map[string]interface{}{"access_value": granted, "tier": tier}).Error; err != nil {
		return fmt.Errorf("error updating tier for %s/%s - %w", username, environment, err)
	}
	return nil
}
