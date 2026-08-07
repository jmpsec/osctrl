package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupFileExplorerHandlers(t *testing.T) (*gorm.DB, *HandlersApi, environments.TLSEnvironment, nodes.OsqueryNode) {
	t.Helper()

	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&logging.OsqueryQueryData{}))

	envs := environments.CreateEnvironment(db)
	nodesmgr := nodes.CreateNodes(db)
	queryManager := queries.CreateQueries(db)
	fileExplorerManager := fileexplorer.NewManager(db, queryManager)
	userManager := users.CreateUserManager(db)
	settingsManager := settings.NewSettings(db)

	env := environments.TLSEnvironment{UUID: "env-uuid", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{UUID: "NODE-UUID", Platform: "linux", EnvironmentID: env.ID, Environment: env.UUID}
	require.NoError(t, db.Create(&node).Error)

	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username:      "alice",
		AccessType:    int(users.AdminLevel),
		AccessValue:   true,
		Environment:   env.UUID,
		EnvironmentID: env.ID,
	}))

	h := CreateHandlersApi(
		WithDB(db),
		WithEnvs(envs),
		WithUsers(userManager),
		WithNodes(nodesmgr),
		WithQueries(queryManager),
		WithSettings(settingsManager),
		WithFileExplorer(fileExplorerManager),
	)
	return db, h, env, node
}

func TestFileExplorerSessionCreateReturnsSession(t *testing.T) {
	_, h, env, node := setupFileExplorerHandlers(t)

	req := fileExplorerRequest(http.MethodPost, "/file-explorer", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.FileExplorerSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp fileExplorerSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotZero(t, resp.Session.ID)
	require.Equal(t, node.UUID, resp.Session.NodeUUID)
	require.Equal(t, "/", resp.Session.Root)
}

func TestFileExplorerSessionCreateDispatchesPrimingRequest(t *testing.T) {
	db, h, env, node := setupFileExplorerHandlers(t)
	req := fileExplorerRequest(http.MethodPost, "/file-explorer", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.FileExplorerSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp fileExplorerSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotNil(t, resp.Priming)
	require.True(t, resp.Priming.Priming)
	require.Equal(t, fileexplorer.ActionPriming, resp.Priming.Action)
	require.NotEmpty(t, resp.Priming.DistributedQueryName)

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Priming.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.FileExplorerQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
}

func TestFileExplorerPrimingResultsReturnsOsqueryInfoRows(t *testing.T) {
	db, h, env, node := setupFileExplorerHandlers(t)
	session, err := h.FileExplorer.CreateSession(env, node, "alice")
	require.NoError(t, err)
	priming, err := h.FileExplorer.SubmitPrimingRequest(session.ID, time.Second)
	require.NoError(t, err)

	result, err := json.Marshal([]map[string]string{{"version": "5.13.1", "build_platform": "linux"}})
	require.NoError(t, err)
	wrapped, err := json.Marshal(types.QueryWriteData{
		Name:   priming.DistributedQueryName,
		Result: result,
		Status: 0,
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{
		UUID:        node.UUID,
		Environment: env.UUID,
		Name:        priming.DistributedQueryName,
		Data:        string(wrapped),
		Status:      0,
	}).Error)
	require.NoError(t, markFileExplorerHandlerNodeQueryStatus(db, priming.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	req := fileExplorerRequest(http.MethodGet, "/file-explorer/metadata", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	req.SetPathValue("request_id", fmt.Sprint(priming.ID))
	rr := httptest.NewRecorder()

	h.FileExplorerPrimingResultsHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var rows []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, "5.13.1", rows[0]["version"])
	require.Equal(t, "linux", rows[0]["build_platform"])
}

func TestFileExplorerSessionCreateRejectsUserWithoutAdminPermission(t *testing.T) {
	_, h, env, node := setupFileExplorerHandlers(t)

	req := fileExplorerRequest(http.MethodPost, "/file-explorer", nil, "bob")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.FileExplorerSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestFileExplorerListCreatesRequest(t *testing.T) {
	db, h, env, node := setupFileExplorerHandlers(t)
	session, err := h.FileExplorer.CreateSession(env, node, "alice")
	require.NoError(t, err)

	req := fileExplorerRequest(http.MethodPost, "/file-explorer/list", []byte(`{"path":"/etc"}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.FileExplorerListHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var request fileexplorer.Request
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &request))
	require.Equal(t, fileexplorer.ActionList, request.Action)
	require.Equal(t, "/etc", request.Path)

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", request.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.FileExplorerQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
}

func TestFileExplorerRequestResultsReturnsEntries(t *testing.T) {
	db, h, env, node := setupFileExplorerHandlers(t)
	session, err := h.FileExplorer.CreateSession(env, node, "alice")
	require.NoError(t, err)
	request, err := h.FileExplorer.ListDirectory(session.ID, "/etc", time.Second)
	require.NoError(t, err)

	result, err := json.Marshal([]map[string]string{{
		"path":      "/etc/hosts",
		"filename":  "hosts",
		"directory": "/etc",
		"type":      "regular",
		"size":      "123",
	}})
	require.NoError(t, err)
	wrapped, err := json.Marshal(types.QueryWriteData{
		Name:   request.DistributedQueryName,
		Result: result,
		Status: 0,
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{
		UUID:        node.UUID,
		Environment: env.UUID,
		Name:        request.DistributedQueryName,
		Data:        string(wrapped),
		Status:      0,
	}).Error)
	require.NoError(t, markFileExplorerHandlerNodeQueryStatus(db, request.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	req := fileExplorerRequest(http.MethodGet, "/file-explorer/results", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	req.SetPathValue("request_id", fmt.Sprint(request.ID))
	rr := httptest.NewRecorder()

	h.FileExplorerRequestResultsHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var entries []fileexplorer.Entry
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &entries))
	require.Equal(t, []fileexplorer.Entry{{
		Path:      "/etc/hosts",
		Filename:  "hosts",
		Directory: "/etc",
		Type:      "regular",
		Size:      123,
	}}, entries)
}

func fileExplorerRequest(method, target string, body []byte, username string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: username})
	return req.WithContext(ctx)
}

func markFileExplorerHandlerNodeQueryStatus(db *gorm.DB, queryName, status string) error {
	var distributed queries.DistributedQuery
	if err := db.Where("name = ?", queryName).First(&distributed).Error; err != nil {
		return err
	}
	return db.Model(&queries.NodeQuery{}).
		Where("query_id = ?", distributed.ID).
		Update("status", status).Error
}
