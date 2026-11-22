package users

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Global roles a group mapping can grant. Superuser is never one of them.
var GroupRoles = []string{"user_admin", "env_manager", "read_only_admin", "alert_admin"}

// Tiers a group mapping can grant for query and carve. The tags tier needs
// per-user scope tags, so it is set by hand only.
var GroupTiers = []string{"standard", "full"}

// GroupMapping gives the members of one IdP group (by display name) global
// roles and environment permissions.
type GroupMapping struct {
	ID           uint             `gorm:"primarykey" json:"-"`
	Group        string           `gorm:"column:group_name;type:varchar(255);uniqueIndex" json:"group"`
	Roles        []string         `gorm:"serializer:json;type:text" json:"roles"`
	Environments []GroupEnvAccess `gorm:"serializer:json;type:text" json:"environments"`
	UpdatedAt    time.Time        `json:"updated_at"`
	UpdatedBy    string           `gorm:"type:varchar(255)" json:"updated_by"`
}

// TableName for GroupMapping
func (GroupMapping) TableName() string { return "user_group_mappings" }

// GroupEnvAccess is the access a group mapping gives in one environment.
type GroupEnvAccess struct {
	// Environment UUID
	Environment string `json:"environment"`
	User        bool   `json:"user"`
	// "" (none), standard or full
	QueryTier string `json:"query_tier"`
	CarveTier string `json:"carve_tier"`
	Admin     bool   `json:"admin"`
}

// GroupGrant is one piece of access a group mapping gave a user, with the
// value it set. Only access with a grant is ever revoked by a mapping.
type GroupGrant struct {
	ID       uint   `gorm:"primarykey"`
	Username string `gorm:"type:varchar(255);uniqueIndex:idx_user_group_grant"`
	// role:<name> or env:<uuid>:<user|query|carve|admin>
	Key   string `gorm:"column:grant_key;type:varchar(128);uniqueIndex:idx_user_group_grant"`
	Value string `gorm:"type:varchar(16)"`
}

// TableName for GroupGrant
func (GroupGrant) TableName() string { return "user_group_grants" }

// UserIdPGroups are the IdP groups last seen for a user, from SCIM or an SSO
// login, so a mapping change can be applied without waiting for either.
type UserIdPGroups struct {
	Username  string   `gorm:"type:varchar(255);primaryKey"`
	Groups    []string `gorm:"serializer:json;type:text"`
	UpdatedAt time.Time
}

// TableName for UserIdPGroups
func (UserIdPGroups) TableName() string { return "user_idp_groups" }

// GroupAccessChange is one grant, change or revoke a mapping made.
type GroupAccessChange struct {
	Username string
	Key      string
	From, To string
}

// String is the audit form: "grant alice env:<uuid>:query=standard".
func (c GroupAccessChange) String() string {
	switch {
	case c.To == "":
		return fmt.Sprintf("revoke %s %s (was %s)", c.Username, c.Key, c.From)
	case c.From == "":
		return fmt.Sprintf("grant %s %s=%s", c.Username, c.Key, c.To)
	}
	return fmt.Sprintf("change %s %s=%s (was %s)", c.Username, c.Key, c.To, c.From)
}

// ErrInvalidGroupMapping is returned for a mapping that cannot be stored.
var ErrInvalidGroupMapping = errors.New("invalid group mapping")

// ValidateGroupMappings checks the mappings; envExists reports whether an
// environment UUID is known.
func ValidateGroupMappings(ms []GroupMapping, envExists func(string) bool) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidGroupMapping, fmt.Sprintf(format, a...))
	}
	seen := map[string]bool{}
	for _, m := range ms {
		if m.Group == "" || len(m.Group) > 255 {
			return bad("group must be 1 to 255 characters")
		}
		// Group names go into audit lines.
		if strings.ContainsFunc(m.Group, unicode.IsControl) {
			return bad("group %q has a control character", m.Group)
		}
		if seen[m.Group] {
			return bad("group %q is mapped twice", m.Group)
		}
		seen[m.Group] = true
		for _, r := range m.Roles {
			if !slices.Contains(GroupRoles, r) {
				return bad("role %q of group %q must be one of %s; superuser is never granted by a mapping", r, m.Group, strings.Join(GroupRoles, ", "))
			}
		}
		envs := map[string]bool{}
		for _, e := range m.Environments {
			if !envExists(e.Environment) {
				return bad("environment %q of group %q does not exist", e.Environment, m.Group)
			}
			if envs[e.Environment] {
				return bad("environment %q is listed twice for group %q", e.Environment, m.Group)
			}
			envs[e.Environment] = true
			for _, t := range []string{e.QueryTier, e.CarveTier} {
				if t != "" && !slices.Contains(GroupTiers, t) {
					return bad("tier %q of group %q must be empty, standard or full", t, m.Group)
				}
			}
		}
	}
	return nil
}

// GroupMappings returns the mappings, by group.
func (m *UserManager) GroupMappings() ([]GroupMapping, error) {
	var ms []GroupMapping
	return ms, m.DB.Order("group_name").Find(&ms).Error
}

// SetGroupMappings replaces every mapping. Callers validate first.
func (m *UserManager) SetGroupMappings(ms []GroupMapping, by string) error {
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&GroupMapping{}).Error; err != nil {
			return err
		}
		for _, g := range ms {
			g.ID, g.UpdatedBy = 0, by
			if g.Roles == nil {
				g.Roles = []string{}
			}
			if g.Environments == nil {
				g.Environments = []GroupEnvAccess{}
			}
			if err := tx.Create(&g).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// desiredAccess is what the mappings give someone in groups, by grant key.
// Several groups combine: any role or bool, and the highest tier.
func desiredAccess(ms []GroupMapping, groups []string) map[string]string {
	out := map[string]string{}
	higher := func(key, tier string) {
		if tier == "" {
			return
		}
		cur, _ := ParseTier(out[key])
		next, _ := ParseTier(tier)
		if next > cur {
			out[key] = tier
		}
	}
	for _, g := range ms {
		if !slices.Contains(groups, g.Group) {
			continue
		}
		for _, r := range g.Roles {
			out["role:"+r] = "true"
		}
		for _, e := range g.Environments {
			p := "env:" + e.Environment + ":"
			if e.User {
				out[p+"user"] = "true"
			}
			if e.Admin {
				out[p+"admin"] = "true"
			}
			higher(p+"query", e.QueryTier)
			higher(p+"carve", e.CarveTier)
		}
	}
	return out
}

var envLevels = map[string]AccessLevel{"user": UserLevel, "query": QueryLevel, "carve": CarveLevel, "admin": AdminLevel}

// accessValue reads the current value of a grant key: "true" or a tier name
// when held, "" when not.
func accessValue(u AdminUser, perms []UserPermission, key string) string {
	if role, ok := strings.CutPrefix(key, "role:"); ok {
		held := map[string]bool{"user_admin": u.UserAdmin, "env_manager": u.EnvManager, "read_only_admin": u.ReadOnlyAdmin, "alert_admin": u.AlertAdmin}[role]
		if held {
			return "true"
		}
		return ""
	}
	env, level := splitEnvKey(key)
	for _, p := range perms {
		if p.Environment != env || p.AccessType != int(envLevels[level]) || !p.AccessValue {
			continue
		}
		if level == "query" || level == "carve" {
			return rowTier(p).String()
		}
		return "true"
	}
	return ""
}

func splitEnvKey(key string) (env, level string) {
	rest := strings.TrimPrefix(key, "env:")
	i := strings.LastIndex(rest, ":")
	return rest[:i], rest[i+1:]
}

// setAccess writes a grant key; "" revokes it.
func (m *UserManager) setAccess(username, key, value string) error {
	if role, ok := strings.CutPrefix(key, "role:"); ok {
		v := value != ""
		var rs RoleSet
		switch role {
		case "user_admin":
			rs.UserAdmin = &v
		case "env_manager":
			rs.EnvManager = &v
		case "read_only_admin":
			rs.ReadOnlyAdmin = &v
		case "alert_admin":
			rs.AlertAdmin = &v
		default:
			return fmt.Errorf("unknown role %q", role)
		}
		return m.SetRoles(username, rs)
	}
	env, level := splitEnvKey(key)
	if level == "query" || level == "carve" {
		t := TierNone
		if value != "" {
			var err error
			if t, err = ParseTier(value); err != nil {
				return err
			}
		}
		return m.SetEnvTier(username, env, envLevels[level], t)
	}
	return m.SetEnvLevel(username, env, envLevels[level], value != "")
}

// SyncGroupAccess stores the IdP groups of username and brings the access the
// mappings gave them in line: it grants what the groups now map to and the
// user does not hold, follows mapping changes for access it granted, and
// revokes access it granted that no group maps any more. Access the user
// holds otherwise (granted by hand) is never changed, and a grant an admin
// changed by hand since becomes theirs. It returns every change, for the
// audit log. An unknown user loses their stored groups and grants.
//
// ponytail: one write per change, not one transaction; a failed sync is fixed
// by the next one, which recomputes everything.
func (m *UserManager) SyncGroupAccess(username string, groups []string) ([]GroupAccessChange, error) {
	exists, u := m.ExistsGet(username)
	if !exists {
		return nil, m.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("username = ?", username).Delete(&GroupGrant{}).Error; err != nil {
				return err
			}
			return tx.Where("username = ?", username).Delete(&UserIdPGroups{}).Error
		})
	}
	stored := UserIdPGroups{Username: username, Groups: slices.Compact(slices.Sorted(slices.Values(groups))), UpdatedAt: time.Now()}
	if stored.Groups == nil {
		stored.Groups = []string{}
	}
	if err := m.DB.Clauses(clause.OnConflict{UpdateAll: true}).Create(&stored).Error; err != nil {
		return nil, err
	}
	ms, err := m.GroupMappings()
	if err != nil {
		return nil, err
	}
	desired := desiredAccess(ms, stored.Groups)
	var grants []GroupGrant
	if err := m.DB.Where("username = ?", username).Find(&grants).Error; err != nil {
		return nil, err
	}
	granted := map[string]string{}
	for _, g := range grants {
		granted[g.Key] = g.Value
	}
	var perms []UserPermission
	if err := m.DB.Where("username = ?", username).Find(&perms).Error; err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(desired)+len(granted))
	for k := range desired {
		keys = append(keys, k)
	}
	for k := range granted {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var changes []GroupAccessChange
	for _, key := range slices.Compact(keys) {
		cur, want, rec := accessValue(u, perms, key), desired[key], granted[key]
		ours := rec != "" && cur == rec
		next := cur
		switch {
		case want != "" && (cur == "" || ours):
			next = want
		case want == "" && ours:
			next = ""
		}
		if next != cur {
			if err := m.setAccess(username, key, next); err != nil {
				return changes, fmt.Errorf("%s: %w", key, err)
			}
			changes = append(changes, GroupAccessChange{Username: username, Key: key, From: cur, To: next})
		}
		// Keep a grant only for access the mapping now holds for the user.
		keep := want != "" && (cur == "" || ours)
		switch {
		case keep && rec != next:
			err = m.DB.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "username"}, {Name: "grant_key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value"}),
			}).Create(&GroupGrant{Username: username, Key: key, Value: next}).Error
		case !keep && rec != "":
			err = m.DB.Where("username = ? AND grant_key = ?", username, key).Delete(&GroupGrant{}).Error
		}
		if err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// GroupAccessUsers lists the users with stored IdP groups.
func (m *UserManager) GroupAccessUsers() ([]UserIdPGroups, error) {
	var out []UserIdPGroups
	return out, m.DB.Order("username").Find(&out).Error
}
