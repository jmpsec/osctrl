package users

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// UserScopeTag grants a user the nodes carrying a tag in one environment; it
// is what the "tags" query/carve tier is scoped to.
type UserScopeTag struct {
	gorm.Model
	Username  string `gorm:"index"`
	EnvUUID   string `gorm:"index"`
	TagID     uint   `gorm:"index"`
	GrantedBy string
}

// ScopeTagIDsContext returns the user's granted tag IDs in an environment,
// using the request cache when present.
func (m *UserManager) ScopeTagIDsContext(ctx context.Context, username, envUUID string) ([]uint, error) {
	cache, hasCache := ctx.Value(permissionContextKey{}).(*permissionCache)
	if hasCache {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if ids, found := cache.scopeTags[username+"\x00"+envUUID]; found {
			return ids, nil
		}
	}
	var ids []uint
	if err := m.DB.WithContext(ctx).Model(&UserScopeTag{}).Where("username = ? AND env_uuid = ?", username, envUUID).Order("tag_id").Pluck("tag_id", &ids).Error; err != nil {
		return nil, err
	}
	if hasCache {
		cache.scopeTags[username+"\x00"+envUUID] = ids
	}
	return ids, nil
}

// SetScopeTags replaces the user's tag set in an environment atomically.
func (m *UserManager) SetScopeTags(username, envUUID, grantedBy string, tagIDs []uint) error {
	if envUUID == NoEnvironment {
		return errBlankPermissionEnv
	}
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("username = ? AND env_uuid = ?", username, envUUID).Delete(&UserScopeTag{}).Error; err != nil {
			return fmt.Errorf("error clearing scope tags - %w", err)
		}
		seen := make(map[uint]bool, len(tagIDs))
		for _, id := range tagIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			if err := tx.Create(&UserScopeTag{Username: username, EnvUUID: envUUID, TagID: id, GrantedBy: grantedBy}).Error; err != nil {
				return fmt.Errorf("error granting scope tag - %w", err)
			}
		}
		return nil
	})
}

// DeleteScopeTagsForTag removes a deleted tag from every user's grants.
func (m *UserManager) DeleteScopeTagsForTag(tagID uint) error {
	return m.DB.Unscoped().Where("tag_id = ?", tagID).Delete(&UserScopeTag{}).Error
}

// scopeTagIDs lists granted tag IDs for a user, optionally for one environment.
func (m *UserManager) scopeTagIDs(username, envUUID string) (map[string][]uint, error) {
	q := m.DB.Where("username = ?", username)
	if envUUID != "" {
		q = q.Where("env_uuid = ?", envUUID)
	}
	var rows []UserScopeTag
	if err := q.Order("tag_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string][]uint)
	for _, r := range rows {
		out[r.EnvUUID] = append(out[r.EnvUUID], r.TagID)
	}
	return out, nil
}
