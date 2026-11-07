package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/vulns"
	"github.com/stretchr/testify/require"
)

func setupReadOnlyRoles(t *testing.T) *HandlersApi {
	t.Helper()
	h := setupUserAdd(t)
	h.Nodes = nodes.CreateNodes(h.DB)
	h.Tags = tags.CreateTagManager(h.DB)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "alerty", AlertAdmin: true}))
	return h
}

func roReq(h *HandlersApi, caller, method, path, body string, vars map[string]string, fn http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range vars {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

func TestReadOnlyGlobalReads(t *testing.T) {
	h := setupReadOnlyRoles(t)
	cases := []struct {
		name string
		fn   http.HandlerFunc
		vars map[string]string
		body string
		want int // status for the read-only admin in this setup
	}{
		{"platforms", h.PlatformsHandler, nil, "", http.StatusOK},
		{"platforms env", h.PlatformsEnvHandler, map[string]string{"env": "uuid-dev"}, "", http.StatusOK},
		{"all tags", h.AllTagsHandler, nil, "", http.StatusOK},
		{"env map", h.EnvironmentMapHandler, map[string]string{"target": "uuid"}, "", http.StatusOK},
		{"health status", h.HealthStatusHandler, nil, "", http.StatusServiceUnavailable},
		{"node lookup", h.LookupNodeHandler, nil, `{"identifier":"nope"}`, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, roReq(h, "ro", http.MethodGet, "/x", c.body, c.vars, c.fn).Code)
			// A plain user and an alert-admin-only user get no global reads.
			require.Equal(t, http.StatusForbidden, roReq(h, "bob", http.MethodGet, "/x", c.body, c.vars, c.fn).Code)
			require.Equal(t, http.StatusForbidden, roReq(h, "alerty", http.MethodGet, "/x", c.body, c.vars, c.fn).Code)
		})
	}
}

func TestAuditAllUsersForReadOnly(t *testing.T) {
	h := setupReadOnlyRoles(t)
	require.NoError(t, h.AuditLog.CreateNew("root", "root did a thing", "127.0.0.1", 1, 1, 0))
	require.NoError(t, h.AuditLog.CreateNew("bob", "bob did a thing", "127.0.0.1", 1, 1, 0))
	count := func(caller string) (int, map[string]bool) {
		rr := roReq(h, caller, http.MethodGet, "/api/v1/audit-logs", "", nil, h.AuditLogsHandler)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var out struct {
			Items []types.AuditLogView `json:"items"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		who := map[string]bool{}
		for _, i := range out.Items {
			who[i.Username] = true
		}
		return len(out.Items), who
	}
	_, who := count("ro")
	require.True(t, who["root"] && who["bob"])
	for _, plain := range []string{"bob", "alerty"} {
		_, who = count(plain)
		require.False(t, who["root"], plain)
	}
	_, who = count("bob")
	require.True(t, who["bob"])
}

// New roles must never reach superuser-only endpoints (Admin + NoEnvironment).
func TestRolesCannotReachSuperuserEndpoints(t *testing.T) {
	h := setupRoles(t)
	h.Vulns = vulns.NewReader(nil, 0) // vulnUser needs it before the permission check
	cases := []struct {
		name string
		fn   http.HandlerFunc
		vars map[string]string
	}{
		{"settings", h.SettingsHandler, nil},
		{"service config", h.ServiceConfigHandler, nil},
		{"log sinks", h.LogSinksListHandler, nil},
		{"auth providers", h.AuthProvidersListHandler, nil},
		{"extensions", h.ExtensionsListHandler, nil},
		{"osquery versions", h.OsqueryVersionsListHandler, nil},
		{"vuln sync", h.VulnSyncRequestHandler, nil},
	}
	for _, c := range cases {
		for _, role := range []string{"ua", "ro", "alerty"} {
			t.Run(c.name+"/"+role, func(t *testing.T) {
				require.Equal(t, http.StatusForbidden, roReq(h, role, http.MethodGet, "/x", "", c.vars, c.fn).Code)
			})
		}
	}
	// env-manager is not in setupRoles; add it here.
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "em", EnvManager: true}))
	for _, c := range cases {
		t.Run(c.name+"/em", func(t *testing.T) {
			require.Equal(t, http.StatusForbidden, roReq(h, "em", http.MethodGet, "/x", "", c.vars, c.fn).Code)
		})
	}
}

func TestReadOnlyReadsVulnFeeds(t *testing.T) {
	h, _, _, _ := setupVulnHandlers(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	feeds := func(user string) int {
		rr := httptest.NewRecorder()
		h.VulnFeedsHandler(rr, vulnRequest(http.MethodGet, "/x", user, nil))
		return rr.Code
	}
	require.Equal(t, http.StatusOK, feeds("ro"))
	require.Equal(t, http.StatusForbidden, feeds("bob"))
}

// Global event topics: read-only gets all, alert admin only alerts. An
// authorized subscription reaches the streaming step, which a recorder
// cannot do (503); a refused one stops at 403.
func TestEventsGlobalTopicsByRole(t *testing.T) {
	h := setupAlertRoles(t)
	h.Events = &testEventSource{ch: make(chan events.Hint)}
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	const allowed = http.StatusServiceUnavailable
	cases := []struct {
		user, topic string
		want        int
	}{
		{"ro", events.Alerts, allowed},
		{"ro", events.ServiceCommands, allowed},
		{"ro", events.Fleet, allowed},
		{"alerty", events.Alerts, allowed},
		{"alerty", events.ServiceCommands, http.StatusForbidden},
		{"alerty", events.Fleet, http.StatusForbidden},
		{"bob", events.Alerts, http.StatusForbidden},
		{"bob", events.Fleet, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.user+"/"+c.topic, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/events?env=all&topic="+c.topic, nil).WithContext(alertsCtx(c.user))
			rr := httptest.NewRecorder()
			h.EventsHandler(rr, req)
			require.Equal(t, c.want, rr.Code, rr.Body.String())
		})
	}
}
