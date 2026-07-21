package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupConsoleHandlers(t *testing.T) (*gorm.DB, *HandlersApi, environments.TLSEnvironment, nodes.OsqueryNode) {
	t.Helper()

	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	envs := environments.CreateEnvironment(db)
	nodesmgr := nodes.CreateNodes(db)
	queryManager := queries.CreateQueries(db)
	consoleManager := console.NewManager(db, queryManager)
	userManager := users.CreateUserManager(db)

	env := environments.TLSEnvironment{UUID: "env-uuid", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{UUID: "NODE-UUID", Platform: "linux", EnvironmentID: env.ID, Environment: env.UUID}
	require.NoError(t, db.Create(&node).Error)

	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username:      "alice",
		AccessType:    int(users.QueryLevel),
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
		WithConsole(consoleManager),
	)
	return db, h, env, node
}

func TestConsoleSessionCreateRequiresQueryPermission(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)

	req := consoleRequest(http.MethodPost, "/console", nil, "bob")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestConsoleSessionCreateRejectsNodeFromOtherEnv(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	otherEnv := environments.TLSEnvironment{UUID: "other-env-uuid", Name: "other-env"}
	require.NoError(t, db.Create(&otherEnv).Error)
	require.NoError(t, db.Model(&node).Updates(map[string]any{"environment_id": otherEnv.ID, "environment": otherEnv.UUID}).Error)

	req := consoleRequest(http.MethodPost, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestConsoleCommandRejectsSecondInFlightCommand(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)

	first := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"ps"}`), "alice")
	first.SetPathValue("env", env.Name)
	first.SetPathValue("session_id", fmt.Sprint(session.ID))
	firstRR := httptest.NewRecorder()
	h.ConsoleCommandCreateHandler(firstRR, first)
	require.Equal(t, http.StatusCreated, firstRR.Code)

	second := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"ls"}`), "alice")
	second.SetPathValue("env", env.Name)
	second.SetPathValue("session_id", fmt.Sprint(session.ID))
	secondRR := httptest.NewRecorder()
	h.ConsoleCommandCreateHandler(secondRR, second)
	require.Equal(t, http.StatusBadRequest, secondRR.Code)
}

func consoleRequest(method, target string, body []byte, username string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: username})
	return req.WithContext(ctx)
}
