package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/logsinks"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupLogSinksHandler(t *testing.T) *HandlersApi {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	if err := db.AutoMigrate(&logsinks.LogSink{}); err != nil {
		t.Fatalf("automigrate log_sinks: %v", err)
	}
	userManager := users.CreateUserManager(db)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice", Admin: true}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"})) // non-admin
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", false)
	require.NoError(t, err)
	h := CreateHandlersApi(
		WithUsers(userManager),
		WithAuditLog(auditLog),
		WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		WithLogSinks(&logsinks.LogSinksManager{DB: db}),
		WithServiceCommands(servicecommands.NewManager(db)),
	)
	return h
}

func logSinksCtx(user string) context.Context {
	return context.WithValue(context.Background(), ContextKey(contextAPI), ContextValue{ctxUser: user})
}

func TestLogSinksListRejectsNonAdmin(t *testing.T) {
	h := setupLogSinksHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-sinks", nil).WithContext(logSinksCtx("bob"))
	rr := httptest.NewRecorder()
	h.LogSinksListHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestLogSinksListRedactsSecretsByDefault(t *testing.T) {
	h := setupLogSinksHandler(t)
	_, err := h.LogSinks.Create("prod-splunk", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"supersecret","host":"h","index":"i"}`, 0, "", nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-sinks", nil).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksListHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got []logSinkDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got, 1)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(got[0].Config, &cfg))
	require.Equal(t, "***", cfg["token"], "token must be redacted without reveal=1")
	require.Equal(t, "http://x", cfg["url"])
}

func TestLogSinksListRevealsSecretsWithRevealFlag(t *testing.T) {
	h := setupLogSinksHandler(t)
	_, err := h.LogSinks.Create("prod-splunk", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"supersecret","host":"h","index":"i"}`, 0, "", nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-sinks?reveal=1", nil).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksListHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got []logSinkDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(got[0].Config, &cfg))
	require.Equal(t, "supersecret", cfg["token"])
}

func TestLogSinksCreateAndRoundTrip(t *testing.T) {
	h := setupLogSinksHandler(t)
	body, _ := json.Marshal(types.LogSinkCreateRequest{
		Name: "s", Type: config.LoggingNone, Enabled: true, Order: 0,
		Config: json.RawMessage(`{}`), EnvironmentID: 0,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-sinks", bytes.NewReader(body)).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	var dto logSinkDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &dto))
	require.NotZero(t, dto.ID)
	require.Equal(t, "s", dto.Name)
	require.Equal(t, config.LoggingNone, dto.Type)
}

func TestLogSinksCreateRejectsInvalidType(t *testing.T) {
	h := setupLogSinksHandler(t)
	body, _ := json.Marshal(types.LogSinkCreateRequest{
		Name: "s", Type: "nope", Config: json.RawMessage(`{}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-sinks", bytes.NewReader(body)).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksCreateHandler(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestLogSinksUpdateMergesSecretPlaceholder(t *testing.T) {
	h := setupLogSinksHandler(t)
	row, err := h.LogSinks.Create("s", config.LoggingSplunk, true, 0, `{"url":"http://x","token":"real-secret","host":"h","index":"i"}`, 0, "", nil)
	require.NoError(t, err)

	body, _ := json.Marshal(types.LogSinkUpdateRequest{
		Name: "s", Type: config.LoggingSplunk, Enabled: false, Order: 5,
		Config: json.RawMessage(`{"url":"http://y","token":"***","host":"h2","index":"j"}`),
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/log-sinks/"+itoa(row.ID), bytes.NewReader(body)).WithContext(logSinksCtx("alice"))
	req.SetPathValue("id", itoa(row.ID))
	rr := httptest.NewRecorder()
	h.LogSinksUpdateHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var dto logSinkDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &dto))
	require.False(t, dto.Enabled)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(dto.Config, &cfg))
	require.Equal(t, "real-secret", cfg["token"], "*** must be merged from previous value")
	require.Equal(t, "http://y", cfg["url"], "non-secret field must be updated")
}

func TestLogSinksDelete(t *testing.T) {
	h := setupLogSinksHandler(t)
	row, err := h.LogSinks.Create("s", config.LoggingNone, true, 0, `{}`, 0, "", nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/log-sinks/"+itoa(row.ID), nil).WithContext(logSinksCtx("alice"))
	req.SetPathValue("id", itoa(row.ID))
	rr := httptest.NewRecorder()
	h.LogSinksDeleteHandler(rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code)

	// Second delete → 404.
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/log-sinks/"+itoa(row.ID), nil).WithContext(logSinksCtx("alice"))
	req2.SetPathValue("id", itoa(row.ID))
	rr2 := httptest.NewRecorder()
	h.LogSinksDeleteHandler(rr2, req2)
	require.Equal(t, http.StatusNotFound, rr2.Code)
}

func TestLogSinksClone(t *testing.T) {
	h := setupLogSinksHandler(t)
	_, err := h.LogSinks.Create("g", config.LoggingNone, true, 0, `{}`, 0, "", nil)
	require.NoError(t, err)

	body, _ := json.Marshal(types.LogSinkCloneRequest{SourceEnvironmentID: 0, TargetEnvironmentID: 5, Overwrite: false})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-sinks/clone", bytes.NewReader(body)).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksCloneHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var got []logSinkDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, uint(5), got[0].EnvironmentID)

	// Clone again without overwrite → 409. Fresh body, same request shape.
	body2, _ := json.Marshal(types.LogSinkCloneRequest{SourceEnvironmentID: 0, TargetEnvironmentID: 5, Overwrite: false})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/log-sinks/clone", bytes.NewReader(body2)).WithContext(logSinksCtx("alice"))
	rr2 := httptest.NewRecorder()
	h.LogSinksCloneHandler(rr2, req2)
	require.Equal(t, http.StatusConflict, rr2.Code)
}

func TestLogSinksApplyQueuesReloadCommand(t *testing.T) {
	h := setupLogSinksHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-sinks/apply", nil).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksApplyHandler(rr, req)
	require.Equal(t, http.StatusAccepted, rr.Code)
	var resp types.ServiceConfigApplyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, config.ServiceTLS, resp.Service)
	require.NotNil(t, resp.Command)
	require.Equal(t, "reload-log-sinks", resp.Command.Action)
}

func TestLogSinksTypesListed(t *testing.T) {
	h := setupLogSinksHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-sinks/types", nil).WithContext(logSinksCtx("alice"))
	rr := httptest.NewRecorder()
	h.LogSinksTypesHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var got []types.LogSinkTypeSpec
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.NotEmpty(t, got)
	// Splunk must be present and flagged as secret-bearing.
	var splunk *types.LogSinkTypeSpec
	for i := range got {
		if got[i].Type == config.LoggingSplunk {
			splunk = &got[i]
		}
	}
	require.NotNil(t, splunk, "splunk type missing from registry response")
	require.True(t, splunk.HasSecret)
	require.Contains(t, splunk.SecretFields, "token")
}

func itoa(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}
