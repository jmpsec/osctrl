package santa

import (
	"errors"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
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

// How GroupTags matches the Santa primary user to an osctrl user.
const (
	MatchExact     = ""           // the username, any case
	MatchLocalPart = "local_part" // the part of the username before "@"
	MatchEmail     = "email"      // the email of the osctrl account
)

// groupUsers returns the osctrl usernames primaryUser matches.
func (m *Manager) groupUsers(match, primaryUser string) ([]string, error) {
	p := strings.ToLower(primaryUser)
	var names []string
	switch match {
	case MatchLocalPart:
		p, _, _ = strings.Cut(p, "@")
		var all []string
		// LIKE narrows the scan; the exact check is in Go, so wildcards in p only widen it.
		if err := m.DB.Model(&UserGroups{}).Where("username = ? OR username LIKE ?", p, p+"@%").Pluck("username", &all).Error; err != nil {
			return nil, err
		}
		for _, n := range all {
			if local, _, _ := strings.Cut(n, "@"); local == p {
				names = append(names, n)
			}
		}
		return names, nil
	case MatchEmail:
		err := m.DB.Table("admin_users").Where("LOWER(email) = ?", p).Pluck("username", &names).Error
		return names, err
	}
	return []string{p}, nil
}

// GroupTags returns the tags the environment maps to the groups of the osctrl
// user that primaryUser matches under the environment's GroupMatch. An unknown
// user has no groups, so no tags; neither does a primary user matching more
// than one osctrl user.
func (m *Manager) GroupTags(envID uint, primaryUser string) ([]string, error) {
	cfg, err := m.Config(envID)
	if err != nil || len(cfg.GroupTags) == 0 || primaryUser == "" {
		return nil, err
	}
	names, err := m.groupUsers(cfg.GroupMatch, primaryUser)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	if len(names) > 1 {
		log.Warn().Uint("env", envID).Str("primary_user", primaryUser).Strs("matches", names).Msg("santa: primary user matches several osctrl users, no IdP group tags")
		return nil, nil
	}
	var ug UserGroups
	err = m.DB.Where("username = ?", strings.ToLower(names[0])).First(&ug).Error
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

// IsApprover reports whether username is in cfg's approver users (any case),
// or in one of its approver groups by the groups last stored from SSO or SCIM.
func (m *Manager) IsApprover(cfg EnvConfig, username string) (bool, error) {
	if slices.ContainsFunc(cfg.ApproverUsers, func(u string) bool { return strings.EqualFold(u, username) }) {
		return true, nil
	}
	if len(cfg.ApproverGroups) == 0 {
		return false, nil
	}
	ug, err := m.UserGroupsOf(username)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(ug.Groups, func(g string) bool { return slices.Contains(cfg.ApproverGroups, g) }), nil
}
