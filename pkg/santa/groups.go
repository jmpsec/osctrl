package santa

import (
	"errors"
	"slices"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GroupTagger is the TaggedBy value of tags applied from IdP groups. Only tags
// with it are removed when membership changes; manual tags are left alone.
const GroupTagger = "santa:idp-groups"

// Caps on what one SSO login can store.
const (
	maxUserGroups = 1000
	maxGroupLen   = 255
)

// SetUserGroups stores the IdP groups of a user from an SSO login.
func (m *Manager) SetUserGroups(username string, groups []string) error {
	kept := make([]string, 0, len(groups))
	for _, g := range groups {
		if g != "" && len(g) <= maxGroupLen && len(kept) < maxUserGroups {
			kept = append(kept, g)
		}
	}
	slices.Sort(kept)
	ug := UserGroups{Username: strings.ToLower(username), Groups: slices.Compact(kept), UpdatedAt: m.now()}
	return m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "username"}},
		DoUpdates: clause.AssignmentColumns([]string{"groups", "updated_at"}),
	}).Create(&ug).Error
}

// UserGroupsOf returns the stored groups of a user; none stored is a zero value.
func (m *Manager) UserGroupsOf(username string) (UserGroups, error) {
	var ugs []UserGroups
	err := m.DB.Where("username = ?", strings.ToLower(username)).Limit(1).Find(&ugs).Error
	if err != nil || len(ugs) == 0 {
		return UserGroups{Username: strings.ToLower(username), Groups: []string{}}, err
	}
	return ugs[0], nil
}

// GroupTags returns the tags the environment maps to the groups of the user
// osctrl knows as primaryUser (exact username, any case). An unknown user has
// no groups, so no tags.
func (m *Manager) GroupTags(envID uint, primaryUser string) ([]string, error) {
	cfg, err := m.Config(envID)
	if err != nil || len(cfg.GroupTags) == 0 || primaryUser == "" {
		return nil, err
	}
	var ug UserGroups
	err = m.DB.Where("username = ?", strings.ToLower(primaryUser)).First(&ug).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, gt := range cfg.GroupTags {
		if slices.Contains(ug.Groups, gt.Group) && !slices.Contains(tags, gt.Tag) {
			tags = append(tags, gt.Tag)
		}
	}
	return tags, nil
}
