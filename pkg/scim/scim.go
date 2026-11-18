// Package scim stores the users and groups an identity provider provisions
// over SCIM 2.0 (RFC 7643, RFC 7644). Each SCIM user is linked to one osctrl
// account, named from userName the way federated login names accounts; the
// API keeps that account in step (create, disable, delete).
package scim

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Schema URNs used on the wire.
const (
	SchemaUser   = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaList   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError  = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// MaxCount caps one page of a list.
const MaxCount = 200

const maxName = 255

// Errors map to SCIM error responses.
var (
	ErrNotFound = errors.New("scim: resource not found")
	ErrConflict = errors.New("scim: userName already exists")
	ErrInvalid  = errors.New("scim: invalid value")
	ErrFilter   = errors.New("scim: unsupported filter")
)

// User is a provisioned user.
type User struct {
	ID         string `gorm:"type:varchar(36);primaryKey"`
	UserName   string `gorm:"type:varchar(255);uniqueIndex"` // lowercase
	ExternalID string `gorm:"type:varchar(255)"`
	Active     bool
	// Username is the linked osctrl account. It is set at creation and kept
	// when userName changes: federated login matches the IdP subject, and
	// permissions are keyed by the account name.
	Username    string `gorm:"type:varchar(255);uniqueIndex"`
	Email       string `gorm:"type:varchar(255)"`
	DisplayName string `gorm:"type:varchar(255)"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TableName for User
func (User) TableName() string { return "scim_users" }

// Group is a provisioned group.
type Group struct {
	ID          string `gorm:"type:varchar(36);primaryKey"`
	DisplayName string `gorm:"type:varchar(255);index"`
	ExternalID  string `gorm:"type:varchar(255)"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TableName for Group
func (Group) TableName() string { return "scim_groups" }

// Member puts a user in a group.
type Member struct {
	GroupID string `gorm:"type:varchar(36);primaryKey"`
	UserID  string `gorm:"type:varchar(36);primaryKey;index"`
}

// TableName for Member
func (Member) TableName() string { return "scim_members" }

// token is the one bearer token the identity provider presents. No row means
// SCIM is off.
type token struct {
	ID        uint   `gorm:"primaryKey"`
	Hash      string `gorm:"type:varchar(64)"`
	CreatedAt time.Time
}

func (token) TableName() string { return "scim_tokens" }

// Ref points at a user or group in a resource.
type Ref struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// Meta is the resource metadata.
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
}

// Name is the user's name. Only a full name is kept.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is one of the user's addresses. Only one address is kept: the
// primary, or else the first.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// UserResource is a user on the wire. Attributes osctrl does not store are
// accepted and dropped.
type UserResource struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Name        *Name    `json:"name,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Groups      []Ref    `json:"groups,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// fullName picks the displayName, or else a name built from its parts.
func (r UserResource) fullName() string {
	if r.DisplayName != "" || r.Name == nil {
		return r.DisplayName
	}
	if r.Name.Formatted != "" {
		return r.Name.Formatted
	}
	return strings.TrimSpace(r.Name.GivenName + " " + r.Name.FamilyName)
}

func pickEmail(es []Email) string {
	for _, e := range es {
		if e.Primary {
			return e.Value
		}
	}
	if len(es) > 0 {
		return es[0].Value
	}
	return ""
}

// GroupResource is a group on the wire.
type GroupResource struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Ref    `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// Operation is one operation of a PATCH request.
type Operation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// PatchRequest is the body of a PATCH request.
type PatchRequest struct {
	Operations []Operation `json:"Operations"`
}

// Filter is a parsed `attr eq "value"` filter, the only form identity
// providers use for lookups. A zero Filter matches everything.
type Filter struct {
	Attr  string // lowercase
	Value string
}

var filterRe = regexp.MustCompile(`^\s*(\w+)\s+(?i:eq)\s+("(?:[^"\\]|\\.)*")\s*$`)

// ParseFilter parses a filter query parameter.
func ParseFilter(s string) (Filter, error) {
	if strings.TrimSpace(s) == "" {
		return Filter{}, nil
	}
	m := filterRe.FindStringSubmatch(s)
	if m == nil {
		return Filter{}, ErrFilter
	}
	v, err := strconv.Unquote(m[2])
	if err != nil {
		return Filter{}, ErrFilter
	}
	return Filter{Attr: strings.ToLower(m[1]), Value: v}, nil
}

// Manager stores SCIM users, groups and the token.
type Manager struct {
	DB  *gorm.DB
	now func() time.Time
}

// NewManager creates the SCIM tables.
func NewManager(db *gorm.DB) (*Manager, error) {
	if err := db.AutoMigrate(&User{}, &Group{}, &Member{}, &token{}); err != nil {
		return nil, err
	}
	return &Manager{DB: db, now: time.Now}, nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// RotateToken replaces the token, which turns SCIM on, and returns it. Only its
// hash is stored.
func (m *Manager) RotateToken() (string, error) {
	t := rand.Text()
	return t, m.DB.Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&token{ID: 1, Hash: hashToken(t), CreatedAt: m.now()}).Error
}

// DisableToken removes the token, which turns SCIM off.
func (m *Manager) DisableToken() error {
	return m.DB.Delete(&token{}, 1).Error
}

// TokenCreated returns when the current token was made, zero when SCIM is off.
func (m *Manager) TokenCreated() (time.Time, error) {
	var ts []token
	err := m.DB.Limit(1).Find(&ts).Error
	if err != nil || len(ts) == 0 {
		return time.Time{}, err
	}
	return ts[0].CreatedAt, nil
}

// CheckToken reports whether presented is the current token.
func (m *Manager) CheckToken(presented string) bool {
	var ts []token
	if presented == "" || m.DB.Limit(1).Find(&ts).Error != nil || len(ts) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(ts[0].Hash), []byte(hashToken(presented))) == 1
}

// Groups returns the display names of the groups of the osctrl account
// username, sorted. An account SCIM does not provision, or whose user is
// inactive, has none.
func (m *Manager) Groups(username string) ([]string, error) {
	names := []string{}
	err := m.DB.Model(&Group{}).
		Joins("JOIN scim_members ON scim_members.group_id = scim_groups.id").
		Joins("JOIN scim_users ON scim_users.id = scim_members.user_id").
		Where("scim_users.username = ? AND scim_users.active = ?", username, true).
		Distinct().Order("scim_groups.display_name").Pluck("scim_groups.display_name", &names).Error
	return names, err
}

// Managed reports whether SCIM provisions the osctrl account username.
func (m *Manager) Managed(username string) (bool, error) {
	var n int64
	err := m.DB.Model(&User{}).Where("username = ?", username).Count(&n).Error
	return n > 0, err
}

// AccountName is the osctrl account name for a SCIM userName, by the rules
// federated login applies to IdP usernames; empty when it is not usable.
func AccountName(userName string) string {
	return utils.SanitizeUsername(userName)
}

func checkName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxName {
		return "", ErrInvalid
	}
	return s, nil
}

func checkExternal(s string) (string, error) {
	if len(s) > maxName {
		return "", ErrInvalid
	}
	return s, nil
}

func page(q *gorm.DB, start, count int) *gorm.DB {
	return q.Order("created_at, id").Offset(max(start, 1) - 1).Limit(min(max(count, 0), MaxCount))
}

// --- users ---

func (m *Manager) userResource(tx *gorm.DB, u User) (UserResource, error) {
	active := u.Active
	r := UserResource{Schemas: []string{SchemaUser}, ID: u.ID, ExternalID: u.ExternalID, UserName: u.UserName, Active: &active,
		DisplayName: u.DisplayName, Meta: &Meta{ResourceType: "User", Created: u.CreatedAt, LastModified: u.UpdatedAt}}
	if u.Email != "" {
		r.Emails = []Email{{Value: u.Email, Primary: true}}
	}
	var gs []Group
	err := tx.Joins("JOIN scim_members ON scim_members.group_id = scim_groups.id").
		Where("scim_members.user_id = ?", u.ID).Order("display_name").Find(&gs).Error
	for _, g := range gs {
		r.Groups = append(r.Groups, Ref{Value: g.ID, Display: g.DisplayName})
	}
	return r, err
}

func getUser(tx *gorm.DB, id string) (User, error) {
	var u User
	err := tx.Where("id = ?", id).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return u, ErrNotFound
	}
	return u, err
}

// saveUser writes u, failing with ErrConflict when another user has its
// userName or its osctrl account.
func saveUser(tx *gorm.DB, u *User) error {
	var n int64
	if err := tx.Model(&User{}).Where("(user_name = ? OR username = ?) AND id <> ?", u.UserName, u.Username, u.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrConflict
	}
	return tx.Save(u).Error
}

func affected(names ...string) []string {
	slices.Sort(names)
	return slices.Compact(names)
}

// setProfile copies userName, externalId, active, email and full name from a
// create or replace request.
func setProfile(u *User, in UserResource) error {
	name, err := checkName(in.UserName)
	if err != nil {
		return err
	}
	if u.ExternalID, err = checkExternal(in.ExternalID); err != nil {
		return err
	}
	if u.Email, err = checkExternal(pickEmail(in.Emails)); err != nil {
		return err
	}
	if u.DisplayName, err = checkExternal(in.fullName()); err != nil {
		return err
	}
	u.UserName = strings.ToLower(name)
	u.Active = in.Active == nil || *in.Active
	return nil
}

// CreateUser provisions a user, active unless the request says otherwise,
// linked to the osctrl account AccountName(userName).
func (m *Manager) CreateUser(in UserResource) (UserResource, User, error) {
	now := m.now()
	u := User{ID: uuid.NewString(), CreatedAt: now, UpdatedAt: now}
	if err := setProfile(&u, in); err != nil {
		return UserResource{}, User{}, err
	}
	if u.Username = AccountName(in.UserName); u.Username == "" {
		return UserResource{}, User{}, ErrInvalid
	}
	var out UserResource
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		if err := saveUser(tx, &u); err != nil {
			return err
		}
		var err error
		out, err = m.userResource(tx, u)
		return err
	})
	return out, u, err
}

// GetUser returns a user.
func (m *Manager) GetUser(id string) (UserResource, error) {
	u, err := getUser(m.DB, id)
	if err != nil {
		return UserResource{}, err
	}
	return m.userResource(m.DB, u)
}

// User returns the stored user, with its linked account.
func (m *Manager) User(id string) (User, error) {
	return getUser(m.DB, id)
}

// ListUsers returns a page of users and how many match the filter. start is
// 1-based.
func (m *Manager) ListUsers(f Filter, start, count int) ([]UserResource, int64, error) {
	q := m.DB.Model(&User{})
	switch f.Attr {
	case "":
	case "username":
		q = q.Where("user_name = ?", strings.ToLower(f.Value))
	case "externalid":
		q = q.Where("external_id = ?", f.Value)
	case "id":
		q = q.Where("id = ?", f.Value)
	default:
		return nil, 0, ErrFilter
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var us []User
	if err := page(q, start, count).Find(&us).Error; err != nil {
		return nil, 0, err
	}
	out := make([]UserResource, 0, len(us))
	for _, u := range us {
		r, err := m.userResource(m.DB, u)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, nil
}

// ReplaceUser sets a user's userName, externalId, active, email and name. The
// linked osctrl account keeps its name.
func (m *Manager) ReplaceUser(id string, in UserResource) (UserResource, User, error) {
	return m.changeUser(id, func(u *User) error { return setProfile(u, in) })
}

// PatchUser applies PATCH operations to a user. Paths osctrl does not store
// are accepted and ignored.
func (m *Manager) PatchUser(id string, ops []Operation) (UserResource, User, error) {
	return m.changeUser(id, func(u *User) error {
		for _, op := range ops {
			switch strings.ToLower(op.Op) {
			case "add", "replace":
				if op.Path == "" {
					var attrs map[string]json.RawMessage
					if err := json.Unmarshal(op.Value, &attrs); err != nil {
						return ErrInvalid
					}
					for k, v := range attrs {
						if err := setUserAttr(u, k, v); err != nil {
							return err
						}
					}
				} else if err := setUserAttr(u, op.Path, op.Value); err != nil {
					return err
				}
			case "remove":
				if strings.EqualFold(op.Path, "externalId") {
					u.ExternalID = ""
				}
			default:
				return ErrInvalid
			}
		}
		return nil
	})
}

func setUserAttr(u *User, attr string, v json.RawMessage) error {
	attr = strings.ToLower(attr)
	if strings.HasPrefix(attr, "emails") {
		// "emails", or a filtered path such as emails[type eq "work"].value.
		var s string
		if json.Unmarshal(v, &s) != nil {
			var es []Email
			if json.Unmarshal(v, &es) != nil {
				return ErrInvalid
			}
			s = pickEmail(es)
		}
		e, err := checkExternal(s)
		u.Email = e
		return err
	}
	switch attr {
	case "displayname":
		var s string
		if json.Unmarshal(v, &s) != nil {
			return ErrInvalid
		}
		s, err := checkExternal(s)
		u.DisplayName = s
		return err
	case "name", "name.formatted":
		// displayName wins; a name only fills in when there is none.
		var n Name
		if attr == "name" && json.Unmarshal(v, &n) != nil || attr != "name" && json.Unmarshal(v, &n.Formatted) != nil {
			return ErrInvalid
		}
		if u.DisplayName == "" {
			s, err := checkExternal(UserResource{Name: &n}.fullName())
			u.DisplayName = s
			return err
		}
	case "active":
		b, err := parseBool(v)
		if err != nil {
			return err
		}
		u.Active = b
	case "username":
		var s string
		if json.Unmarshal(v, &s) != nil {
			return ErrInvalid
		}
		s, err := checkName(s)
		if err != nil {
			return err
		}
		u.UserName = strings.ToLower(s)
	case "externalid":
		var s string
		if json.Unmarshal(v, &s) != nil {
			return ErrInvalid
		}
		s, err := checkExternal(s)
		if err != nil {
			return err
		}
		u.ExternalID = s
	}
	return nil
}

// parseBool reads a JSON boolean, or the "True"/"False" string Entra ID sends.
func parseBool(v json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b, nil
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		if b, err := strconv.ParseBool(s); err == nil {
			return b, nil
		}
	}
	return false, ErrInvalid
}

func (m *Manager) changeUser(id string, change func(*User) error) (UserResource, User, error) {
	var out UserResource
	var u User
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		if u, err = getUser(tx, id); err != nil {
			return err
		}
		if err := change(&u); err != nil {
			return err
		}
		u.UpdatedAt = m.now()
		if err := saveUser(tx, &u); err != nil {
			return err
		}
		out, err = m.userResource(tx, u)
		return err
	})
	return out, u, err
}

// DeleteUser removes a user and its memberships, and returns it.
func (m *Manager) DeleteUser(id string) (User, error) {
	var u User
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		if u, err = getUser(tx, id); err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&Member{}).Error; err != nil {
			return err
		}
		return tx.Delete(&u).Error
	})
	return u, err
}

// --- groups ---

func getGroup(tx *gorm.DB, id string) (Group, error) {
	var g Group
	err := tx.Where("id = ?", id).First(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return g, ErrNotFound
	}
	return g, err
}

// memberNames returns the osctrl accounts of a group's members.
func memberNames(tx *gorm.DB, groupID string) ([]string, error) {
	var names []string
	err := tx.Model(&User{}).Joins("JOIN scim_members ON scim_members.user_id = scim_users.id").
		Where("scim_members.group_id = ?", groupID).Pluck("scim_users.username", &names).Error
	return names, err
}

func (m *Manager) groupResource(tx *gorm.DB, g Group, members bool) (GroupResource, error) {
	r := GroupResource{Schemas: []string{SchemaGroup}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.DisplayName,
		Meta: &Meta{ResourceType: "Group", Created: g.CreatedAt, LastModified: g.UpdatedAt}}
	if !members {
		return r, nil
	}
	var us []User
	err := tx.Joins("JOIN scim_members ON scim_members.user_id = scim_users.id").
		Where("scim_members.group_id = ?", g.ID).Order("user_name").Find(&us).Error
	for _, u := range us {
		r.Members = append(r.Members, Ref{Value: u.ID, Display: u.UserName})
	}
	return r, err
}

// groupState is a group being changed, with its member IDs.
type groupState struct {
	Group
	members map[string]bool
}

func refIDs(v json.RawMessage) ([]string, error) {
	var refs []Ref
	if len(v) == 0 || string(v) == "null" {
		return nil, nil
	}
	if err := json.Unmarshal(v, &refs); err != nil {
		return nil, ErrInvalid
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.Value)
	}
	return ids, nil
}

// saveGroup writes the group and its members after checking every member is a
// provisioned user. It returns the userNames of the members before and after.
func (m *Manager) saveGroup(tx *gorm.DB, s groupState) ([]string, error) {
	var err error
	if s.DisplayName, err = checkName(s.DisplayName); err != nil {
		return nil, err
	}
	if s.ExternalID, err = checkExternal(s.ExternalID); err != nil {
		return nil, err
	}
	before, err := memberNames(tx, s.ID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(s.members))
	for id := range s.members {
		ids = append(ids, id)
	}
	// ponytail: one IN list per write; chunk it if groups pass ~30k members.
	var n int64
	if len(ids) > 0 {
		if err := tx.Model(&User{}).Where("id IN ?", ids).Count(&n).Error; err != nil {
			return nil, err
		}
	}
	if n != int64(len(ids)) {
		return nil, ErrInvalid
	}
	if err := tx.Save(&s.Group).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("group_id = ?", s.ID).Delete(&Member{}).Error; err != nil {
		return nil, err
	}
	rows := make([]Member, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, Member{GroupID: s.ID, UserID: id})
	}
	if len(rows) > 0 {
		if err := tx.CreateInBatches(rows, 500).Error; err != nil {
			return nil, err
		}
	}
	after, err := memberNames(tx, s.ID)
	return affected(append(before, after...)...), err
}

func membersOf(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// CreateGroup provisions a group with its members.
func (m *Manager) CreateGroup(in GroupResource) (GroupResource, []string, error) {
	now := m.now()
	s := groupState{Group{ID: uuid.NewString(), DisplayName: in.DisplayName, ExternalID: in.ExternalID, CreatedAt: now, UpdatedAt: now}, map[string]bool{}}
	for _, r := range in.Members {
		s.members[r.Value] = true
	}
	return m.writeGroup(s)
}

func (m *Manager) writeGroup(s groupState) (GroupResource, []string, error) {
	var out GroupResource
	var names []string
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		if names, err = m.saveGroup(tx, s); err != nil {
			return err
		}
		out, err = m.groupResource(tx, s.Group, true)
		return err
	})
	return out, names, err
}

// GetGroup returns a group, with its members unless members is false.
func (m *Manager) GetGroup(id string, members bool) (GroupResource, error) {
	g, err := getGroup(m.DB, id)
	if err != nil {
		return GroupResource{}, err
	}
	return m.groupResource(m.DB, g, members)
}

// ListGroups returns a page of groups and how many match the filter.
func (m *Manager) ListGroups(f Filter, start, count int, members bool) ([]GroupResource, int64, error) {
	q := m.DB.Model(&Group{})
	switch f.Attr {
	case "":
	case "displayname":
		q = q.Where("display_name = ?", f.Value)
	case "externalid":
		q = q.Where("external_id = ?", f.Value)
	case "id":
		q = q.Where("id = ?", f.Value)
	default:
		return nil, 0, ErrFilter
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var gs []Group
	if err := page(q, start, count).Find(&gs).Error; err != nil {
		return nil, 0, err
	}
	out := make([]GroupResource, 0, len(gs))
	for _, g := range gs {
		r, err := m.groupResource(m.DB, g, members)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, nil
}

func (m *Manager) loadGroup(id string) (groupState, error) {
	g, err := getGroup(m.DB, id)
	if err != nil {
		return groupState{}, err
	}
	var ids []string
	if err := m.DB.Model(&Member{}).Where("group_id = ?", id).Pluck("user_id", &ids).Error; err != nil {
		return groupState{}, err
	}
	return groupState{g, membersOf(ids)}, nil
}

// ReplaceGroup sets a group's displayName, externalId and members.
func (m *Manager) ReplaceGroup(id string, in GroupResource) (GroupResource, []string, error) {
	s, err := m.loadGroup(id)
	if err != nil {
		return GroupResource{}, nil, err
	}
	s.DisplayName, s.ExternalID, s.UpdatedAt = in.DisplayName, in.ExternalID, m.now()
	s.members = map[string]bool{}
	for _, r := range in.Members {
		s.members[r.Value] = true
	}
	return m.writeGroup(s)
}

var memberPathRe = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]$`)

// PatchGroup applies PATCH operations to a group: membership changes in the
// forms Okta and Entra ID send, and displayName and externalId.
func (m *Manager) PatchGroup(id string, ops []Operation) (GroupResource, []string, error) {
	s, err := m.loadGroup(id)
	if err != nil {
		return GroupResource{}, nil, err
	}
	for _, op := range ops {
		if err := patchGroup(&s, op); err != nil {
			return GroupResource{}, nil, err
		}
	}
	s.UpdatedAt = m.now()
	return m.writeGroup(s)
}

func patchGroup(s *groupState, op Operation) error {
	kind := strings.ToLower(op.Op)
	path := strings.ToLower(op.Path)
	switch kind {
	case "add", "replace":
		if path == "" {
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &attrs); err != nil {
				return ErrInvalid
			}
			for k, v := range attrs {
				if err := setGroupAttr(s, kind, k, v); err != nil {
					return err
				}
			}
			return nil
		}
		return setGroupAttr(s, kind, path, op.Value)
	case "remove":
		if m := memberPathRe.FindStringSubmatch(op.Path); m != nil {
			id, err := strconv.Unquote(m[1])
			if err != nil {
				return ErrInvalid
			}
			delete(s.members, id)
			return nil
		}
		switch path {
		case "members":
			ids, err := refIDs(op.Value)
			if err != nil {
				return err
			}
			if ids == nil {
				clear(s.members)
			}
			for _, id := range ids {
				delete(s.members, id)
			}
		case "externalid":
			s.ExternalID = ""
		}
		return nil
	}
	return ErrInvalid
}

func setGroupAttr(s *groupState, kind, attr string, v json.RawMessage) error {
	switch strings.ToLower(attr) {
	case "displayname":
		if json.Unmarshal(v, &s.DisplayName) != nil {
			return ErrInvalid
		}
	case "externalid":
		if json.Unmarshal(v, &s.ExternalID) != nil {
			return ErrInvalid
		}
	case "members":
		ids, err := refIDs(v)
		if err != nil {
			return err
		}
		if kind == "replace" {
			clear(s.members)
		}
		for _, id := range ids {
			s.members[id] = true
		}
	}
	return nil
}

// DeleteGroup removes a group and its memberships.
func (m *Manager) DeleteGroup(id string) ([]string, error) {
	var names []string
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := getGroup(tx, id); err != nil {
			return err
		}
		var err error
		if names, err = memberNames(tx, id); err != nil {
			return err
		}
		if err := tx.Where("group_id = ?", id).Delete(&Member{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&Group{}).Error
	})
	return affected(names...), err
}
