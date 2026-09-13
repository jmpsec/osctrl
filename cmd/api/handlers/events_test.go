package handlers

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

type testEventSource struct {
	ch            chan events.Hint
	cancelled     atomic.Bool
	environmentID atomic.Uint32
}

func (s *testEventSource) Subscribe(_ string, environmentID uint, _ []string) (<-chan events.Hint, func(), error) {
	s.environmentID.Store(uint32(environmentID))
	return s.ch, func() { s.cancelled.Store(true) }, nil
}

func TestEventSubscriptionValidation(t *testing.T) {
	_, h, _, _ := setupConsoleHandlers(t)
	h.Events = &testEventSource{ch: make(chan events.Hint)}
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	for _, tc := range []struct {
		query, user string
		code        int
	}{
		{"", "alice", 400},
		{"?env=env&topic=console", "alice", 400},
		{"?env=env&env=other&topic=queries", "alice", 400},
		{"?env=env&topic=queries&token=secret", "alice", 400},
		{"?env=env&topic=queries", "bob", 403},
		{"?env=missing&topic=queries", "alice", 404},
	} {
		r := consoleRequest(http.MethodGet, "/api/v1/events"+tc.query, nil, tc.user)
		w := httptest.NewRecorder()
		h.EventsHandler(w, r)
		require.Equal(t, tc.code, w.Code, tc.query)
	}
}

func TestEventStreamAllowsAllAlertsSubscription(t *testing.T) {
	h := setupAlertsHandler(t)
	source := &testEventSource{ch: make(chan events.Hint, 1)}
	h.Events = source
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"})
		h.EventsHandler(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/events?env=all&topic=alerts", nil)
	require.NoError(t, err)
	response, err := srv.Client().Do(r)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.EqualValues(t, 0, source.environmentID.Load())
	reader := bufio.NewReader(response.Body)
	frame := func() string {
		var result strings.Builder
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			result.WriteString(line)
			if line == "\n" {
				return result.String()
			}
		}
	}
	require.Contains(t, frame(), `"environment_uuid":"all"`)
	source.ch <- events.Hint{EnvironmentID: 42, Topic: events.Alerts, Name: events.ChangeHistory, Change: events.ChangeHistory}
	got := frame()
	require.Contains(t, got, `"topic":"alerts"`)
	require.Contains(t, got, `"change":"history"`)
}

func TestEventStreamRejectsAlertsForNonAdmin(t *testing.T) {
	h := setupAlertsHandler(t)
	h.Events = &testEventSource{ch: make(chan events.Hint)}
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?env=all&topic=alerts", nil).WithContext(alertsCtx("bob"))
	rr := httptest.NewRecorder()
	h.EventsHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestEventOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		origin, site string
		want         bool
	}{
		{"", "same-origin", true}, {"https://example.com", "same-origin", true},
		{"https://evil.example", "cross-site", false}, {"https://example.com.evil", "", false},
		{"null", "", false}, {"https://example.com/path", "", false}, {"", "same-site", false},
	} {
		r := httptest.NewRequest("GET", "https://example.com/api/v1/events", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		require.Equal(t, tc.want, eventOriginAllowed(r), tc.origin+" "+tc.site)
	}
}

func TestEventStreamRevocationAndCleanup(t *testing.T) {
	for _, revokeToken := range []bool{true, false} {
		t.Run(map[bool]string{true: "token", false: "permissions"}[revokeToken], func(t *testing.T) {
			db, h, env, _ := setupConsoleHandlers(t)
			source := &testEventSource{ch: make(chan events.Hint, 1)}
			h.Events = source
			var valid atomic.Bool
			valid.Store(true)
			h.EventsAuthenticate = func(*http.Request) bool { return valid.Load() }
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"})
				h.EventsHandler(w, r.WithContext(ctx))
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/events?env=env&topic=queries", nil)
			require.NoError(t, err)
			response, err := srv.Client().Do(r)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, 200, response.StatusCode)
			require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			reader := bufio.NewReader(response.Body)
			frame := func() string {
				var result strings.Builder
				for {
					line, err := reader.ReadString('\n')
					require.NoError(t, err)
					result.WriteString(line)
					if line == "\n" {
						return result.String()
					}
				}
			}
			require.Contains(t, frame(), "stream.ready")
			source.ch <- events.Hint{EnvironmentID: env.ID, Topic: events.Queries, Name: "query-1", Change: events.ChangeResults}
			queryFrame := frame()
			require.Contains(t, queryFrame, "query-1")
			require.Contains(t, queryFrame, `"change":"results"`)
			if revokeToken {
				valid.Store(false)
			} else {
				require.NoError(t, db.Model(&users.UserPermission{}).Where("username = ?", "alice").Update("access_value", false).Error)
			}
			source.ch <- events.Hint{EnvironmentID: env.ID, Topic: events.Queries, Name: "secret-after-revocation"}
			last := frame()
			require.Contains(t, last, "auth.expired")
			require.NotContains(t, last, "secret-after-revocation")
			require.Eventually(t, source.cancelled.Load, time.Second, time.Millisecond)
		})
	}
}

func TestEventStreamFiltersConsoleSessionHints(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	source := &testEventSource{ch: make(chan events.Hint, 2)}
	h.Events = source
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"})
		h.EventsHandler(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/events?env=env&topic=console&console_session=%d", srv.URL, session.ID), nil)
	require.NoError(t, err)
	response, err := srv.Client().Do(r)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	reader := bufio.NewReader(response.Body)
	frame := func() string {
		var result strings.Builder
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			result.WriteString(line)
			if line == "\n" {
				return result.String()
			}
		}
	}
	require.Contains(t, frame(), "stream.ready")
	source.ch <- events.Hint{EnvironmentID: env.ID, Topic: events.Console, Name: "wrong-session", Change: events.ChangeResults, SessionID: session.ID + 1, ResourceID: 11}
	source.ch <- events.Hint{EnvironmentID: env.ID, Topic: events.Console, Name: "right-session", Change: events.ChangeResults, SessionID: session.ID, ResourceID: 12}
	got := frame()
	require.Contains(t, got, "right-session")
	require.Contains(t, got, `"session_id":`)
	require.Contains(t, got, `"resource_id":12`)
	require.NotContains(t, got, "wrong-session")
}

func TestEventStreamRejectsConsoleSessionOwnedByAnotherUser(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{
		Username:      "bob",
		AccessType:    int(users.AdminLevel),
		AccessValue:   true,
		Environment:   env.UUID,
		EnvironmentID: env.ID,
	}))
	h.Events = &testEventSource{ch: make(chan events.Hint)}
	h.EventsAuthenticate = func(*http.Request) bool { return true }
	req := consoleRequest(http.MethodGet, fmt.Sprintf("/api/v1/events?env=env&topic=console&console_session=%d", session.ID), nil, "bob")
	rr := httptest.NewRecorder()
	h.EventsHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}
