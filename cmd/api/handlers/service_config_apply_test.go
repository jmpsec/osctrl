package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupServiceConfigApplyHandler(t *testing.T) (*HandlersApi, chan struct{}) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	userManager := users.CreateUserManager(db)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice", Admin: true}))
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", false)
	require.NoError(t, err)
	restartCh := make(chan struct{}, 1)
	h := CreateHandlersApi(
		WithUsers(userManager),
		WithAuditLog(auditLog),
		WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		WithRestartCh(restartCh),
		WithServiceCommands(servicecommands.NewManager(db)),
	)
	return h, restartCh
}

func serviceConfigApplyRequest(t *testing.T, service string) *http.Request {
	t.Helper()
	body, err := json.Marshal(types.ServiceConfigApplyRequest{Service: service})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/service-config/apply", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	return req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"}))
}

// TestServiceConfigApplyHandlerRestartsAPI covers the branch the SPA's
// "Apply & Restart" hits for osctrl-api: the 202 goes out AND the restart
// signal reaches main, which drains before exiting.
func TestServiceConfigApplyHandlerRestartsAPI(t *testing.T) {
	h, restartCh := setupServiceConfigApplyHandler(t)
	req := serviceConfigApplyRequest(t, config.ServiceAPI)
	rr := httptest.NewRecorder()

	h.ServiceConfigApplyHandler(rr, req)

	require.Equal(t, http.StatusAccepted, rr.Code)
	select {
	case <-restartCh:
	default:
		t.Fatal("api apply must signal the restart channel")
	}
	var resp types.ServiceConfigApplyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, config.ServiceAPI, resp.Service)
	// The API restarts itself in-process; there is no queued command to poll.
	require.Nil(t, resp.Command)
}

// An empty body means "this service", so a bare POST restarts the API
// rather than falling through to the invalid-service branch.
func TestServiceConfigApplyHandlerDefaultsToAPI(t *testing.T) {
	h, restartCh := setupServiceConfigApplyHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/service-config/apply", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"}))
	rr := httptest.NewRecorder()

	h.ServiceConfigApplyHandler(rr, req)

	require.Equal(t, http.StatusAccepted, rr.Code)
	select {
	case <-restartCh:
	default:
		t.Fatal("bodyless apply must signal the restart channel")
	}
}

// Without a wired channel the endpoint has to say so, not accept and drop.
func TestServiceConfigApplyHandlerWithoutRestartCh(t *testing.T) {
	h, _ := setupServiceConfigApplyHandler(t)
	h.RestartCh = nil
	rr := httptest.NewRecorder()

	h.ServiceConfigApplyHandler(rr, serviceConfigApplyRequest(t, config.ServiceAPI))

	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestServiceConfigApplyHandlerQueuesTLSRestart(t *testing.T) {
	h, restartCh := setupServiceConfigApplyHandler(t)
	req := serviceConfigApplyRequest(t, config.ServiceTLS)
	rr := httptest.NewRecorder()

	h.ServiceConfigApplyHandler(rr, req)

	require.Equal(t, http.StatusAccepted, rr.Code)
	select {
	case <-restartCh:
		t.Fatal("TLS apply must not restart osctrl-api")
	default:
	}
	var resp types.ServiceConfigApplyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, config.ServiceTLS, resp.Service)
	require.NotNil(t, resp.Command)
	require.Equal(t, servicecommands.StatusPending, resp.Command.Status)
	require.NotEmpty(t, resp.Command.CommandID)
}
