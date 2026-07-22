package console_test

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupConsoleManager(t *testing.T) (*gorm.DB, *console.Manager, environments.TLSEnvironment, nodes.OsqueryNode) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&environments.TLSEnvironment{}, &nodes.OsqueryNode{}, &logging.OsqueryQueryData{}))

	env := environments.TLSEnvironment{UUID: "env-uuid", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{UUID: "NODE-UUID", Platform: "linux", EnvironmentID: env.ID, Environment: env.UUID}
	require.NoError(t, db.Create(&node).Error)

	queryManager := queries.CreateQueries(db)
	return db, console.NewManager(db, queryManager), env, node
}

func TestCreateSessionDefaultsCWDByPlatform(t *testing.T) {
	_, manager, env, node := setupConsoleManager(t)
	node.Platform = "windows"

	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	require.Equal(t, `C:\`, session.CWD)
	require.True(t, session.Active)
	require.Equal(t, node.UUID, session.NodeUUID)
}

func TestSubmitLocalCommandDoesNotCreateDistributedQuery(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	command, parsed, err := manager.SubmitCommand(session.ID, "pwd")
	require.NoError(t, err)
	require.Equal(t, console.StatusCompleted, command.Status)
	require.Equal(t, console.CommandLocal, parsed.Kind)

	var count int64
	require.NoError(t, db.Model(&queries.DistributedQuery{}).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestSubmitRemoteCommandCreatesHiddenConsoleQuery(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	command, parsed, err := manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)
	require.Equal(t, console.StatusQueued, command.Status)
	require.Equal(t, console.CommandRemote, parsed.Kind)
	require.NotEmpty(t, command.DistributedQueryName)

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", command.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.ConsoleQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
	require.True(t, distributed.Active)
	require.Equal(t, uint(1), uint(distributed.Expected))

	var nodeQuery queries.NodeQuery
	require.NoError(t, db.Where("query_id = ?", distributed.ID).First(&nodeQuery).Error)
	require.Equal(t, node.ID, nodeQuery.NodeID)
}

func TestSubmitRejectsWhenCommandInFlight(t *testing.T) {
	_, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	_, _, err = manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)
	_, _, err = manager.SubmitCommand(session.ID, "ls")
	require.Error(t, err)
	require.Contains(t, err.Error(), "pending")
}

func TestCloseSessionExpiresPendingCommands(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	command, _, err := manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)

	require.NoError(t, manager.CloseSession(session.ID))

	var refreshed console.Command
	require.NoError(t, db.First(&refreshed, command.ID).Error)
	require.Equal(t, console.StatusExpired, refreshed.Status)
	require.NotNil(t, refreshed.ExpiredAt)
}

func TestRefreshCommandStatusFromNodeQuery(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	command, _, err := manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)

	require.NoError(t, markNodeQueryStatus(db, command.DistributedQueryName, queries.DistributedQueryStatusCompleted))
	got, err := manager.RefreshCommandStatus(command.ID)
	require.NoError(t, err)
	require.Equal(t, console.StatusCompleted, got.Status)
	require.NotNil(t, got.CompletedAt)
}

func TestRefreshCommandStatusMarksError(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	command, _, err := manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)

	require.NoError(t, markNodeQueryStatus(db, command.DistributedQueryName, queries.DistributedQueryStatusError))
	got, err := manager.RefreshCommandStatus(command.ID)
	require.NoError(t, err)
	require.Equal(t, console.StatusError, got.Status)
	require.NotNil(t, got.CompletedAt)
}

func TestRefreshCDUpdatesWorkingDirectoryAfterResult(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	command, parsed, err := manager.SubmitCommand(session.ID, "cd /etc")
	require.NoError(t, err)

	data, err := json.Marshal([]map[string]string{{"path": "/etc", "type": "directory"}})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{Name: command.DistributedQueryName, Data: string(data), Status: 0}).Error)
	require.NoError(t, markNodeQueryStatus(db, command.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	got, err := manager.RefreshCommandStatus(command.ID)
	require.NoError(t, err)
	require.Equal(t, console.StatusCompleted, got.Status)
	require.Equal(t, "/etc", parsed.Path)

	var refreshed console.Session
	require.NoError(t, db.First(&refreshed, session.ID).Error)
	require.Equal(t, "/etc", refreshed.CWD)
}

func TestCommandResultsDecodeStoredQueryWriteData(t *testing.T) {
	db, manager, env, node := setupConsoleManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	command, _, err := manager.SubmitCommand(session.ID, "ps")
	require.NoError(t, err)

	result, err := json.Marshal([]map[string]string{{"pid": "1", "name": "launchd"}})
	require.NoError(t, err)
	wrapped, err := json.Marshal(map[string]any{
		"name":    command.DistributedQueryName,
		"result":  json.RawMessage(result),
		"status":  0,
		"message": "",
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{Name: command.DistributedQueryName, Data: string(wrapped), Status: 0}).Error)
	require.NoError(t, markNodeQueryStatus(db, command.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	rows, err := manager.CommandResults(command.ID)
	require.NoError(t, err)
	require.Equal(t, []map[string]any{{"pid": "1", "name": "launchd"}}, rows)
}

func markNodeQueryStatus(db *gorm.DB, name, status string) error {
	var distributed queries.DistributedQuery
	if err := db.Where("name = ?", name).First(&distributed).Error; err != nil {
		return err
	}
	return db.Model(&queries.NodeQuery{}).Where("query_id = ?", distributed.ID).Update("status", status).Error
}
