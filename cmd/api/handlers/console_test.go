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

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
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
	carveManager := carves.CreateFileCarves(db, config.CarverDB, nil)
	consoleManager := console.NewManager(db, queryManager)
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
		WithCarves(carveManager),
		WithSettings(settingsManager),
		WithConsole(consoleManager),
	)
	return db, h, env, node
}

func TestConsoleSessionCreateReturnsHistory(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	oldSession, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	_, _, err = h.Console.SubmitCommand(oldSession.ID, "pwd")
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	var resp consoleSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotZero(t, resp.Session.ID)
	require.Len(t, resp.History, 1)
	require.Equal(t, "pwd", resp.History[0].Command.Input)
}

func TestConsoleSessionCreateDispatchesPrimingCommand(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	req := consoleRequest(http.MethodPost, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotNil(t, resp.Priming)
	require.True(t, resp.Priming.Priming)
	require.Equal(t, console.StatusQueued, resp.Priming.Status)
	require.NotEmpty(t, resp.Priming.DistributedQueryName)

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Priming.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.ConsoleQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
}

func TestWarmupQueryWaitCoversFullPollInterval(t *testing.T) {
	// last_query_read is stamped by osctrl-tls's batch writer and can lag
	// the node's real poll by up to a flush window, so it must not shrink
	// the warmup window: every warming-up command reserves a full interval
	// regardless of how fresh or stale the recorded read looks.
	require.Equal(t, 60*time.Second, warmupQueryWait(environments.TLSEnvironment{QueryInterval: 60}))
	// A recorded read (fresh or stale) must not change the reservation.
	require.Equal(t, 60*time.Second, warmupQueryWait(environments.TLSEnvironment{QueryInterval: 60}))
	// Unset interval falls back to the environment default.
	require.Equal(t, 60*time.Second, warmupQueryWait(environments.TLSEnvironment{}))
	// Very long intervals are capped so requests cannot pend unbounded.
	require.Equal(t, maxWarmupWait, warmupQueryWait(environments.TLSEnvironment{QueryInterval: 3600}))
}

func TestConsoleSessionCreatePrimingSurvivesNodePollInterval(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, db.Model(&env).UpdateColumn("query_interval", 60).Error)
	// The node's recorded read is mid-cycle on its regular distributed
	// interval; the priming query must still be pending when its next
	// read arrives.
	before := time.Now()

	req := consoleRequest(http.MethodPost, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	var resp consoleSessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotNil(t, resp.Priming)
	require.NotNil(t, resp.Priming.ExpiresAt, "the response must expose the deadline so clients can wait it out")

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Priming.DistributedQueryName).First(&distributed).Error)
	// Base is the minute floor plus the full warmup wait (60s interval).
	require.True(t, distributed.Expiration.After(before.Add(115*time.Second)), "priming must cover the node's next scheduled read")
	require.True(t, distributed.Expiration.Before(before.Add(125*time.Second)))
}

func TestConsoleSessionCreateReturnsNodeInfo(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, db.Model(&node).Updates(map[string]any{
		"ip_address":       "10.0.0.8",
		"osquery_user":     "root",
		"osquery_version":  "5.11.0",
		"platform":         "darwin",
		"platform_version": "14.5",
	}).Error)

	req := consoleRequest(http.MethodPost, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp struct {
		NodeInfo struct {
			IPAddress       string `json:"ip_address"`
			OsqueryUser     string `json:"osquery_user"`
			OsqueryVersion  string `json:"osquery_version"`
			Platform        string `json:"platform"`
			PlatformVersion string `json:"platform_version"`
		} `json:"node_info"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "10.0.0.8", resp.NodeInfo.IPAddress)
	require.Equal(t, "root", resp.NodeInfo.OsqueryUser)
	require.Equal(t, "5.11.0", resp.NodeInfo.OsqueryVersion)
	require.Equal(t, "darwin", resp.NodeInfo.Platform)
	require.Equal(t, "14.5", resp.NodeInfo.PlatformVersion)
}

func TestConsoleSessionCreateRejectsUserWithoutAdminPermission(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)

	req := consoleRequest(http.MethodPost, "/console", nil, "bob")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestConsoleSessionCreateRejectsQueryOnlyUser(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{
		Username:      "bob",
		AccessType:    int(users.QueryLevel),
		AccessValue:   true,
		Environment:   env.UUID,
		EnvironmentID: env.ID,
	}))

	req := consoleRequest(http.MethodPost, "/console", nil, "bob")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("uuid", node.UUID)
	rr := httptest.NewRecorder()

	h.ConsoleSessionCreateHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestConsoleSessionShowRefreshesSession(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	oldUpdatedAt := time.Now().Add(-time.Hour)
	require.NoError(t, db.Model(&session).UpdateColumn("updated_at", oldUpdatedAt).Error)
	before := time.Now()

	req := consoleRequest(http.MethodGet, "/console", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleSessionShowHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var refreshed console.Session
	require.NoError(t, db.First(&refreshed, session.ID).Error)
	require.False(t, refreshed.UpdatedAt.Before(before))
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

func TestConsoleCommandExpirationUsesDoubleAcceleratedQueryReadInterval(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceTLS, settings.AcceleratedSeconds, 7, settings.NoEnvironmentID))
	// The expiration is the doubled accelerated interval plus the full
	// warmup wait (60s default interval).
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	before := time.Now()

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"ps"}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Command.DistributedQueryName).First(&distributed).Error)
	require.True(t, distributed.Expiration.After(before.Add(73*time.Second)))
	require.True(t, distributed.Expiration.Before(before.Add(76*time.Second)))
}

func TestConsoleCommandExpirationSurvivesNodePollIntervalWhileWarmingUp(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceTLS, settings.AcceleratedSeconds, 7, settings.NoEnvironmentID))
	require.NoError(t, db.Model(&env).UpdateColumn("query_interval", 60).Error)
	// The node's last recorded read looks overdue, but the batch writer
	// lag means its next real read can still be a full interval away. The
	// query must stay pending at least that long, or warmup commands
	// expire undelivered and the operator has to keep clicking refresh
	// until acceleration happens to kick in.
	require.NoError(t, db.Model(&node).UpdateColumn("last_query_read", time.Now().Add(-2*time.Minute)).Error)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)
	before := time.Now()

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"ps"}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotNil(t, resp.Command.ExpiresAt, "the response must expose the deadline so clients can wait it out")
	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Command.DistributedQueryName).First(&distributed).Error)
	require.True(t, distributed.Expiration.After(before.Add(73*time.Second)), "expiration must cover the node's next scheduled read despite stale check-in data")
	require.True(t, distributed.Expiration.Before(before.Add(76*time.Second)))
}

func TestConsoleOsqueryModeSQLUsesLongerExpiration(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceTLS, settings.AcceleratedSeconds, 5, settings.NoEnvironmentID))
	require.NoError(t, db.Model(&env).UpdateColumn("query_interval", 60).Error)
	// The sql timeout floor is a minute; the full warmup wait (60s) is
	// added on top so delivery is covered while still warming up.
	session, _ := h.Console.CreateSession(env, node, "alice")
	before := time.Now()

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"select * from osquery_info","osquery_mode":true}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Command.DistributedQueryName).First(&distributed).Error)
	require.True(t, distributed.Expiration.After(before.Add(119*time.Second)))
	require.True(t, distributed.Expiration.Before(before.Add(122*time.Second)))
}

func TestConsoleCommandRejectsNonAdminSessionOwner(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{
		Username:      "bob",
		AccessType:    int(users.QueryLevel),
		AccessValue:   true,
		Environment:   env.UUID,
		EnvironmentID: env.ID,
	}))
	session, err := h.Console.CreateSession(env, node, "bob")
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"ps"}`), "bob")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestConsoleGetCreatesNodeTargetedCarve(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	session, err := h.Console.CreateSession(env, node, "alice")
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":"get /etc/passwd"}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, console.CommandCarve, resp.Parsed.Kind)
	require.Equal(t, console.StatusCompleted, resp.Command.Status)
	require.Contains(t, resp.Parsed.Message, "carve")

	var carveQuery queries.DistributedQuery
	require.NoError(t, db.Where("type = ?", queries.CarveQueryType).First(&carveQuery).Error)
	require.Equal(t, "/etc/passwd", carveQuery.Path)
	require.Equal(t, "console:alice", carveQuery.Creator)
	require.Equal(t, 1, carveQuery.Expected)

	var nodeQuery queries.NodeQuery
	require.NoError(t, db.Where("query_id = ?", carveQuery.ID).First(&nodeQuery).Error)
	require.Equal(t, node.ID, nodeQuery.NodeID)

	targets, err := h.Queries.GetTargets(carveQuery.Name)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "uuid", targets[0].Type)
	require.Equal(t, node.UUID, targets[0].Value)
}

func TestConsoleOsqueryModeTablesUsesLoadedTablesForNodePlatform(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	require.NoError(t, db.Model(&node).Update("platform", "linux").Error)
	h.OsqueryTables = []types.OsqueryTable{
		{Name: "apps", Platforms: []string{"darwin"}},
		{Name: "file", Platforms: []string{}},
		{Name: "processes", Platforms: []string{"linux", "darwin"}},
		{Name: "rpm_packages", Platforms: []string{"linux"}},
	}
	session, err := h.Console.CreateSession(env, nodes.OsqueryNode{
		ID:            node.ID,
		UUID:          node.UUID,
		Platform:      "linux",
		EnvironmentID: env.ID,
		Environment:   env.UUID,
	}, "alice")
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":".tables","osquery_mode":true}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, console.CommandLocal, resp.Parsed.Kind)
	require.Equal(t, "tables", resp.Parsed.Command)
	require.Contains(t, resp.Parsed.Output, "file")
	require.Contains(t, resp.Parsed.Output, "processes")
	require.Contains(t, resp.Parsed.Output, "rpm_packages")
	require.NotContains(t, resp.Parsed.Output, "apps")
}

func TestConsoleOsqueryModeTablesTreatsLinuxDistrosAsLinux(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	h.OsqueryTables = []types.OsqueryTable{
		{Name: "apps", Platforms: []string{"darwin"}},
		{Name: "deb_packages", Platforms: []string{"linux"}},
		{Name: "file", Platforms: []string{}},
	}
	session, err := h.Console.CreateSession(env, nodes.OsqueryNode{
		ID:            node.ID,
		UUID:          node.UUID,
		Platform:      "debian",
		EnvironmentID: env.ID,
		Environment:   env.UUID,
	}, "alice")
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/console", []byte(`{"input":".tables","osquery_mode":true}`), "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("session_id", fmt.Sprint(session.ID))
	rr := httptest.NewRecorder()

	h.ConsoleCommandCreateHandler(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var resp consoleCommandResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Contains(t, resp.Parsed.Output, "deb_packages")
	require.Contains(t, resp.Parsed.Output, "file")
	require.NotContains(t, resp.Parsed.Output, "apps")
}

func consoleRequest(method, target string, body []byte, username string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: username})
	return req.WithContext(ctx)
}
