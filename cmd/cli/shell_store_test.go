package main

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestNodeToRowActiveInactive(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		seen   time.Time
		hours  int64
		active bool
	}{
		{"fresh", now, 24, true},
		{"just_within", now.Add(-23 * time.Hour), 24, true},
		{"stale", now.Add(-48 * time.Hour), 24, false},
		{"zero_hours_defaults_active", now.Add(-1 * time.Hour), 0, true},
		{"zero_hours_defaults_to_72", now.Add(-48 * time.Hour), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := nodes.OsqueryNode{UUID: "ABC", Hostname: "h", LastSeen: c.seen, Environment: "dev"}
			row := nodeToRow(n, c.hours)
			if row.Active != c.active {
				t.Fatalf("expected active=%v got %v", c.active, row.Active)
			}
			if row.UUID != "ABC" {
				t.Fatalf("uuid not mapped: %q", row.UUID)
			}
		})
	}
}

func TestQueryStatus(t *testing.T) {
	cases := []struct {
		q    queries.DistributedQuery
		want string
	}{
		{queries.DistributedQuery{Active: true}, "ACTIVE"},
		{queries.DistributedQuery{Completed: true}, "COMPLETE"},
		{queries.DistributedQuery{Expired: true}, "EXPIRED"},
		{queries.DistributedQuery{Deleted: true}, "DELETED"},
		{queries.DistributedQuery{}, "—"},
	}
	for _, c := range cases {
		if got := queryStatus(c.q); got != c.want {
			t.Fatalf("queryStatus: got %q want %q", got, c.want)
		}
	}
}

func TestCsvSplit(t *testing.T) {
	got := csvSplit("a, b ,, c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d got %q want %q", i, got[i], want[i])
		}
	}
	if csvSplit("") != nil {
		t.Fatalf("empty should be nil")
	}
}

func TestParseHidden(t *testing.T) {
	for _, v := range []string{"yes", "Y", "true", "1"} {
		if !parseHidden(v) {
			t.Fatalf("expected hidden for %q", v)
		}
	}
	for _, v := range []string{"", "no", "0", "x"} {
		if parseHidden(v) {
			t.Fatalf("expected not hidden for %q", v)
		}
	}
}

func TestAPIStoreSettings(t *testing.T) {
	r := newParityRig(t)
	sm := seedSettings(t, r)
	s := &apiStore{api: r.API}
	rows, err := s.Settings()
	require.NoError(t, err)
	require.Len(t, rows, 3)
	require.NoError(t, s.UpdateSetting("tls", "i-set", "integer", "9"))
	v, _ := sm.RetrieveValue("tls", "i-set", settings.NoEnvironmentID)
	require.Equal(t, int64(9), v.Integer)
	require.NoError(t, s.UpdateSetting("tls", "b-set", "bool", "yes"))
	v, _ = sm.RetrieveValue("tls", "b-set", settings.NoEnvironmentID)
	require.True(t, v.Boolean)
	require.NoError(t, s.UpdateSetting("tls", "b-set", "boolean", "off"))
	v, _ = sm.RetrieveValue("tls", "b-set", settings.NoEnvironmentID)
	require.False(t, v.Boolean)
	require.ErrorContains(t, s.UpdateSetting("tls", "b-set", "boolean", "maybe"), "not true/false")
	require.NoError(t, s.UpdateSetting("tls", "i-set", "int", "11"))
	require.Error(t, s.UpdateSetting("tls", "i-set", "integer", "abc"))
	require.Error(t, s.AddSetting("tls", "x", "string", "v"))
	require.Error(t, s.DeleteSetting("tls", "x"))
}

func TestAPIStorePermissions(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	r.SeedUser("bob", false)
	require.NoError(t, r.Users.ChangeAccess("bob", env.UUID, users.EnvAccess{User: true, Carve: true}))
	rows, err := (&apiStore{api: r.API}).Permissions("bob")
	require.NoError(t, err)
	want := map[string]bool{"user": true, "query": false, "carve": true, "admin": false}
	require.Len(t, rows, len(want))
	for _, row := range rows {
		require.Equal(t, "bob", row.Username)
		require.Equal(t, env.UUID, row.Environment)
		require.Equal(t, want[row.AccessType], row.AccessValue, row.AccessType)
	}
	_, err = (&apiStore{api: r.API}).Permissions("ghost")
	require.Error(t, err)
}
