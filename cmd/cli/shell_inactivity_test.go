package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type inactivityTransport func(*http.Request) (*http.Response, error)

func (f inactivityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdateInactiveHoursPreservesExistingValue(t *testing.T) {
	oldSettings := settingsmgr
	t.Cleanup(func() { settingsmgr = oldSettings })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	settingsmgr = settings.NewSettings(db)
	require.NoError(t, settingsmgr.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 168, 0))
	before, err := settingsmgr.RetrieveValue(config.ServiceAPI, settings.InactiveHours, 0)
	require.NoError(t, err)
	store := &dbStore{}
	for _, tc := range []struct{ typ, value string }{
		{"integer", "0"}, {"integer", "-1"}, {"int", "2562048"},
		{"integer", "2.5"}, {"integer", "9223372036854775808"},
		{"string", "24"}, {"boolean", "true"}, {"unknown", "24"},
	} {
		t.Run(tc.typ+"_"+tc.value, func(t *testing.T) {
			require.Error(t, store.UpdateSetting(config.ServiceAPI, settings.InactiveHours, tc.typ, tc.value))
			after, err := settingsmgr.RetrieveValue(config.ServiceAPI, settings.InactiveHours, 0)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
	require.NoError(t, store.UpdateSetting(config.ServiceAPI, settings.InactiveHours, "int", "24"))
	after, err := settingsmgr.RetrieveValue(config.ServiceAPI, settings.InactiveHours, 0)
	require.NoError(t, err)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, int64(24), after.Integer)
}

func TestCLIEnvironmentThresholds(t *testing.T) {
	oldEnvs, oldNodes, oldQueries, oldSettings := envs, nodesmgr, queriesmgr, settingsmgr
	t.Cleanup(func() { envs, nodesmgr, queriesmgr, settingsmgr = oldEnvs, oldNodes, oldQueries, oldSettings })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs, nodesmgr, queriesmgr, settingsmgr = environments.CreateEnvironment(db), nodes.CreateNodes(db), queries.CreateQueries(db), settings.NewSettings(db)
	require.NoError(t, settingsmgr.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, 0))
	fixtures := map[string]nodes.OsqueryNode{}
	envFixtures := map[string]environments.TLSEnvironment{}
	hours := map[string]int64{"short": 2, "long": 168, "inherited": 24}
	for _, name := range []string{"short", "long", "inherited"} {
		e := envs.Empty(name, name+".example.com")
		require.NoError(t, envs.Create(&e))
		if name != "inherited" {
			require.NoError(t, settingsmgr.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, hours[name], e.ID))
		}
		n := nodes.OsqueryNode{UUID: strings.ToUpper(name), Environment: name, EnvironmentID: e.ID, LastSeen: time.Now().Add(-48 * time.Hour)}
		require.NoError(t, db.Create(&n).Error)
		fixtures[name], envFixtures[name] = n, e
	}
	dbStore := &dbStore{}
	stats, err := dbStore.Stats()
	require.NoError(t, err)
	require.Equal(t, int64(24), stats.InactiveHours)
	require.Equal(t, int64(3), stats.TotalNodes)
	require.Equal(t, int64(1), stats.ActiveNodes)
	require.Equal(t, int64(2), stats.InactiveNodes)
	require.Len(t, stats.Environments, 3)
	for _, e := range stats.Environments {
		require.Equal(t, hours[e.Name], e.InactiveHours)
	}

	thresholdRequests := 0
	api, err := apiclient.CreateAPIWithTransport(apiclient.JSONConfigurationAPI{URL: "http://osctrl.test", Token: "test"}, inactivityTransport(func(r *http.Request) (*http.Response, error) {
		parts := strings.Split(r.URL.Path, "/")
		var body any
		switch {
		case r.URL.Path == "/api/v1/stats":
			body = stats
		case strings.HasPrefix(r.URL.Path, "/api/v1/environments/inactive-hours/"):
			thresholdRequests++
			name := parts[5]
			for n, e := range envFixtures {
				if name == e.UUID {
					name = n
				}
			}
			body = map[string]any{"inactive_hours": hours[name], "source": "environment", "override_hours": hours[name]}
		case strings.HasPrefix(r.URL.Path, "/api/v1/nodes/"):
			name := parts[4]
			for n, e := range envFixtures {
				if name == e.UUID {
					name = n
				}
			}
			if len(parts) == 7 {
				body = fixtures[name]
			} else {
				body = []nodes.OsqueryNode{fixtures[name]}
			}
		default:
			t.Fatalf("unexpected API request: %s", r.URL.Path)
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	}))
	require.NoError(t, err)
	for _, store := range []DataStore{dbStore, newAPIStore(api)} {
		t.Run(store.Mode(), func(t *testing.T) {
			gotStats, err := store.Stats()
			require.NoError(t, err)
			require.Equal(t, stats, gotStats)
			for name, e := range envFixtures {
				for _, env := range []string{name, e.UUID} {
					rows, err := store.Nodes(env, "all")
					require.NoError(t, err)
					require.Len(t, rows, 1)
					require.Equal(t, name == "long", rows[0].Active, env)
					row, err := store.Node(env, fixtures[name].UUID)
					require.NoError(t, err)
					require.Equal(t, rows[0].Active, row.Active, env)
				}
			}
		})
	}
	require.Equal(t, 12, thresholdRequests)
	for name := range envFixtures {
		rows, err := dbStore.Nodes(name, "active")
		require.NoError(t, err)
		if name == "long" {
			require.Len(t, rows, 1)
		} else {
			require.Empty(t, rows)
		}
	}
}
