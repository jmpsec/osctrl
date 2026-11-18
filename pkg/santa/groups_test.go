package santa

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupTags(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", GroupTags: []GroupTag{
		{Group: "Finance", Tag: "finance"}, {Group: "Accounting", Tag: "finance"}, {Group: "Engineering", Tag: "eng"},
	}}))
	require.NoError(t, m.SetUserGroups("JDoe", []string{"Accounting", "Finance", "", strings.Repeat("x", 256)}))
	for _, tt := range []struct {
		name, user string
		env        uint
		want       []string
	}{
		{"exact username, any case", "jdoe", 1, []string{"finance"}},
		{"no partial match", "jdoe@example.com", 1, nil},
		{"unknown user", "bob", 1, nil},
		{"no primary user", "", 1, nil},
		{"env without mappings", "jdoe", 2, nil},
	} {
		got, err := m.GroupTags(tt.env, tt.user)
		require.NoError(t, err, tt.name)
		require.Equal(t, tt.want, got, tt.name)
	}

	// A later login replaces the groups; invalid ones were dropped.
	var ug UserGroups
	require.NoError(t, m.DB.First(&ug, "username = ?", "jdoe").Error)
	require.Equal(t, []string{"Accounting", "Finance"}, ug.Groups)
	require.NoError(t, m.SetUserGroups("jdoe", []string{"Engineering"}))
	got, err := m.GroupTags(1, "JDOE")
	require.NoError(t, err)
	require.Equal(t, []string{"eng"}, got)
}

func TestGroupTagsMatch(t *testing.T) {
	m := newTestManager(t)
	type adminUser struct{ Username, Email string }
	require.NoError(t, m.DB.Table("admin_users").AutoMigrate(&adminUser{}))
	require.NoError(t, m.DB.Table("admin_users").Create([]adminUser{
		{"jdoe@example.com", "jdoe@example.com"}, {"asmith", "Ann.Smith@Example.com"},
		{"x1", "dup@example.com"}, {"x2", "dup@example.com"},
	}).Error)
	for u, g := range map[string]string{
		"jdoe@example.com": "Finance", "asmith": "Finance", "x1": "Finance", "x2": "Finance",
		"bob@a.example": "Finance", "bob@b.example": "Finance", "j_doe@example.com": "Finance",
	} {
		require.NoError(t, m.SetUserGroups(u, []string{g}))
	}
	finance := []string{"finance"}
	for _, tt := range []struct {
		name, match, user string
		want              []string
	}{
		{"exact ignores local part", MatchExact, "jdoe", nil},
		{"local part", MatchLocalPart, "JDoe", finance},
		{"local part of an email", MatchLocalPart, "jdoe@corp.example", finance},
		{"local part, plain username", MatchLocalPart, "asmith", finance},
		{"local part, LIKE wildcard is literal", MatchLocalPart, "j%", nil},
		{"local part, ambiguous", MatchLocalPart, "bob", nil},
		{"email, any case", MatchEmail, "ann.smith@example.com", finance},
		{"email, not the username", MatchEmail, "asmith", nil},
		{"email, ambiguous", MatchEmail, "dup@example.com", nil},
	} {
		require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", GroupMatch: tt.match,
			GroupTags: []GroupTag{{Group: "Finance", Tag: "finance"}}}), tt.name)
		got, err := m.GroupTags(1, tt.user)
		require.NoError(t, err, tt.name)
		require.Equal(t, tt.want, got, tt.name)
	}
	require.Error(t, ValidateConfig(&EnvConfig{ClientMode: "MONITOR", GroupMatch: "domain"}))
}

func TestValidateGroupTags(t *testing.T) {
	many := make([]GroupTag, MaxGroupTags+1)
	for i := range many {
		many[i] = GroupTag{Group: "g", Tag: strings.Repeat("t", i+1)}
	}
	for _, tt := range []struct {
		name string
		gts  []GroupTag
	}{
		{"too many", many},
		{"empty group", []GroupTag{{Group: " ", Tag: "t"}}},
		{"empty tag", []GroupTag{{Group: "g"}}},
		{"long group", []GroupTag{{Group: strings.Repeat("g", 256), Tag: "t"}}},
		{"newline", []GroupTag{{Group: "a\nb", Tag: "t"}}},
	} {
		require.Error(t, ValidateConfig(&EnvConfig{ClientMode: "MONITOR", GroupTags: tt.gts}), tt.name)
	}
	c := EnvConfig{ClientMode: "MONITOR", GroupTags: []GroupTag{{Group: " g ", Tag: "t"}, {Group: "g", Tag: "t"}}}
	require.NoError(t, ValidateConfig(&c))
	require.Equal(t, []GroupTag{{Group: "g", Tag: "t"}}, c.GroupTags)
}
