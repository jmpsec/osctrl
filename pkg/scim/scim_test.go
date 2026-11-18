package scim

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := NewManager(db)
	require.NoError(t, err)
	return m
}

func ops(t *testing.T, s string) []Operation {
	t.Helper()
	var p PatchRequest
	require.NoError(t, json.Unmarshal([]byte(s), &p))
	return p.Operations
}

func TestParseFilter(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want Filter
		err  error
	}{
		{"", Filter{}, nil},
		{`userName eq "jdoe@example.com"`, Filter{"username", "jdoe@example.com"}, nil},
		{`displayName EQ "Finance \"EU\""`, Filter{"displayname", `Finance "EU"`}, nil},
		{`userName co "j"`, Filter{}, ErrFilter},
		{`userName eq "a" or userName eq "b"`, Filter{}, ErrFilter},
	} {
		got, err := ParseFilter(tt.in)
		require.ErrorIs(t, err, tt.err, tt.in)
		require.Equal(t, tt.want, got, tt.in)
	}
}

func TestToken(t *testing.T) {
	m := newTestManager(t)
	require.False(t, m.CheckToken(""))
	require.False(t, m.CheckToken("x"))
	t1, err := m.RotateToken()
	require.NoError(t, err)
	require.True(t, m.CheckToken(t1))
	t2, err := m.RotateToken()
	require.NoError(t, err)
	require.False(t, m.CheckToken(t1))
	require.True(t, m.CheckToken(t2))
	created, err := m.TokenCreated()
	require.NoError(t, err)
	require.False(t, created.IsZero())
	require.NoError(t, m.DisableToken())
	require.False(t, m.CheckToken(t2))
	created, err = m.TokenCreated()
	require.NoError(t, err)
	require.True(t, created.IsZero())
}

func TestUsersAndGroups(t *testing.T) {
	testUsersAndGroups(t, newTestManager(t))
}

// The membership queries join, DISTINCT and ORDER BY, which PostgreSQL is
// stricter about than SQLite.
func TestUsersAndGroupsExternalBackend(t *testing.T) {
	for _, backend := range []string{"POSTGRES", "MYSQL"} {
		t.Run(backend, func(t *testing.T) {
			dsn := os.Getenv("OSCTRL_TEST_" + backend + "_DSN")
			if dsn == "" {
				t.Skip("set OSCTRL_TEST_" + backend + "_DSN to test this engine")
			}
			dialect := postgres.Open(dsn)
			if backend == "MYSQL" {
				dialect = mysql.Open(dsn)
			}
			db, err := gorm.Open(dialect, &gorm.Config{})
			require.NoError(t, err)
			if db.Migrator().HasTable(&User{}) {
				t.Skip("scim_users already exists; use an empty test database")
			}
			m, err := NewManager(db)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&User{}, &Group{}, &Member{}, &token{})) })
			testUsersAndGroups(t, m)
		})
	}
}

func TestAccountName(t *testing.T) {
	for in, want := range map[string]string{
		"JDoe@Example.com": "jdoe@example.com", // email-shaped names are lowercased, as in SSO
		"jdoe":             "jdoe",
		"j doe":            "",
		" ":                "",
	} {
		require.Equal(t, want, AccountName(in), in)
	}
}

func testUsersAndGroups(t *testing.T, m *Manager) {
	alice, acct, err := m.CreateUser(UserResource{UserName: "Alice@Example.com", ExternalID: "a1",
		Emails: []Email{{Value: "a@home.example"}, {Value: "alice@example.com", Primary: true}}, Name: &Name{GivenName: "Alice", FamilyName: "A"}})
	require.NoError(t, err)
	require.True(t, *alice.Active)
	require.Equal(t, "alice@example.com", acct.Username)
	require.Equal(t, "alice@example.com", acct.Email)
	require.Equal(t, "Alice A", acct.DisplayName)
	require.Equal(t, []Email{{Value: "alice@example.com", Primary: true}}, alice.Emails)
	_, _, err = m.CreateUser(UserResource{UserName: "alice@example.com"})
	require.ErrorIs(t, err, ErrConflict)
	_, _, err = m.CreateUser(UserResource{UserName: "not a name"})
	require.ErrorIs(t, err, ErrInvalid)
	bob, _, err := m.CreateUser(UserResource{UserName: "bob", DisplayName: "Bob"})
	require.NoError(t, err)

	got, total, err := m.ListUsers(Filter{"username", "ALICE@example.com"}, 1, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, alice.ID, got[0].ID)
	_, _, err = m.ListUsers(Filter{"emails", "x"}, 1, 100)
	require.ErrorIs(t, err, ErrFilter)

	fin, names, err := m.CreateGroup(GroupResource{DisplayName: "Finance", Members: []Ref{{Value: alice.ID}}})
	require.NoError(t, err)
	require.Equal(t, []string{"alice@example.com"}, names)
	_, _, err = m.CreateGroup(GroupResource{DisplayName: "Ghosts", Members: []Ref{{Value: "nope"}}})
	require.ErrorIs(t, err, ErrInvalid)

	// Entra ID adds and removes with a value list.
	_, names, err = m.PatchGroup(fin.ID, ops(t, `{"Operations":[{"op":"Add","path":"members","value":[{"value":"`+bob.ID+`"}]}]}`))
	require.NoError(t, err)
	require.Equal(t, []string{"alice@example.com", "bob"}, names)
	g, err := m.Groups("bob")
	require.NoError(t, err)
	require.Equal(t, []string{"Finance"}, g)

	// Okta removes with a filtered path and renames with a pathless replace.
	_, names, err = m.PatchGroup(fin.ID, ops(t, `{"Operations":[
		{"op":"remove","path":"members[value eq \"`+bob.ID+`\"]"},
		{"op":"replace","value":{"id":"`+fin.ID+`","displayName":"Finance EU"}}]}`))
	require.NoError(t, err)
	require.Equal(t, []string{"alice@example.com", "bob"}, names)
	g, err = m.Groups("bob")
	require.NoError(t, err)
	require.Empty(t, g)
	g, err = m.Groups("alice@example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"Finance EU"}, g)

	// Entra ID deactivates with a string and sets the work email by path; an
	// inactive user has no groups.
	u, acct, err := m.PatchUser(alice.ID, ops(t, `{"Operations":[
		{"op":"Replace","path":"active","value":"False"},
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"alice@corp.example"},
		{"op":"Replace","path":"displayName","value":"Alice Anders"}]}`))
	require.NoError(t, err)
	require.False(t, *u.Active)
	require.False(t, acct.Active)
	require.Equal(t, "alice@corp.example", acct.Email)
	require.Equal(t, "Alice Anders", acct.DisplayName)
	g, err = m.Groups("alice@example.com")
	require.NoError(t, err)
	require.Empty(t, g)
	// Okta reactivates and renames; the osctrl account keeps its name.
	u, acct, err = m.PatchUser(alice.ID, ops(t, `{"Operations":[{"op":"replace","value":{"active":true,"userName":"alice2","name":{"givenName":"A"}}}]}`))
	require.NoError(t, err)
	require.Equal(t, "alice2", u.UserName)
	require.Equal(t, "alice@example.com", acct.Username)
	require.Equal(t, "Alice Anders", acct.DisplayName)
	require.Equal(t, []Ref{{Value: fin.ID, Display: "Finance EU"}}, u.Groups)
	_, _, err = m.PatchUser(alice.ID, ops(t, `{"Operations":[{"op":"replace","path":"userName","value":"bob"}]}`))
	require.ErrorIs(t, err, ErrConflict)

	ok, err := m.Managed("alice@example.com")
	require.NoError(t, err)
	require.True(t, ok)

	// PUT replaces the members.
	gr, names, err := m.ReplaceGroup(fin.ID, GroupResource{DisplayName: "Finance", Members: []Ref{{Value: bob.ID}}})
	require.NoError(t, err)
	require.Equal(t, []Ref{{Value: bob.ID, Display: "bob"}}, gr.Members)
	require.Equal(t, []string{"alice@example.com", "bob"}, names)

	names, err = m.DeleteGroup(fin.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"bob"}, names)
	_, err = m.GetGroup(fin.ID, true)
	require.ErrorIs(t, err, ErrNotFound)

	gone, err := m.DeleteUser(bob.ID)
	require.NoError(t, err)
	require.Equal(t, "bob", gone.Username)
	ok, err = m.Managed("bob")
	require.NoError(t, err)
	require.False(t, ok)
}
