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
