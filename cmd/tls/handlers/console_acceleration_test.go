package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestShouldAccelerateQueryReadForActiveConsoleSession(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&console.Session{}))
	queryManager := queries.CreateQueries(db)
	handler := &HandlersTLS{Queries: queryManager}
	node := nodes.OsqueryNode{ID: 7, UUID: "NODE-UUID", EnvironmentID: 1}
	otherNode := nodes.OsqueryNode{ID: 8, UUID: "OTHER-NODE-UUID", EnvironmentID: 1}

	require.False(t, handler.shouldAccelerateQueryRead(node, false))
	require.True(t, handler.shouldAccelerateQueryRead(node, true))

	require.NoError(t, db.Model(&console.Session{}).Create(map[string]any{
		"environment_id": 1,
		"node_id":        node.ID,
		"node_uuid":      "NODE-UUID",
		"creator":        "alice",
		"cwd":            "/",
		"platform":       "linux",
		"active":         false,
	}).Error)
	require.False(t, handler.shouldAccelerateQueryRead(node, false))

	require.NoError(t, db.Create(&console.Session{
		EnvironmentID: 1,
		NodeID:        otherNode.ID,
		NodeUUID:      otherNode.UUID,
		Creator:       "alice",
		CWD:           "/",
		Platform:      "linux",
		Active:        true,
	}).Error)
	require.False(t, handler.shouldAccelerateQueryRead(node, false))
	require.True(t, handler.shouldAccelerateQueryRead(otherNode, false))

	require.NoError(t, db.Create(&console.Session{
		EnvironmentID: 2,
		NodeID:        node.ID,
		NodeUUID:      node.UUID,
		Creator:       "alice",
		CWD:           "/",
		Platform:      "linux",
		Active:        true,
	}).Error)
	require.False(t, handler.shouldAccelerateQueryRead(node, false))

	staleSession := console.Session{
		EnvironmentID: node.EnvironmentID,
		NodeID:        node.ID,
		NodeUUID:      node.UUID,
		Creator:       "alice",
		CWD:           "/",
		Platform:      "linux",
		Active:        true,
	}
	require.NoError(t, db.Create(&staleSession).Error)
	require.NoError(t, db.Model(&staleSession).UpdateColumn("updated_at", time.Now().Add(-consoleSessionFreshness-time.Minute)).Error)
	require.False(t, handler.shouldAccelerateQueryRead(node, false))

	require.NoError(t, db.Create(&console.Session{
		EnvironmentID: node.EnvironmentID,
		NodeID:        node.ID,
		NodeUUID:      node.UUID,
		Creator:       "alice",
		CWD:           "/",
		Platform:      "linux",
		Active:        true,
	}).Error)
	require.True(t, handler.shouldAccelerateQueryRead(node, false))
}

func TestQueryReadAcceleratesOnlyConsoleSessionNode(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesMgr := nodes.CreateNodes(db)
	queryManager := queries.CreateQueries(db)
	settingsMgr := settings.NewSettings(db)
	require.NoError(t, db.AutoMigrate(&console.Session{}))
	require.NoError(t, settingsMgr.NewIntegerValue(config.ServiceTLS, settings.AcceleratedSeconds, 5, settings.NoEnvironmentID))

	env := environments.TLSEnvironment{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "env",
	}
	require.NoError(t, db.Create(&env).Error)
	consoleNode := nodes.OsqueryNode{
		NodeKey:       "console-node-key",
		UUID:          "CONSOLE-NODE-UUID",
		EnvironmentID: env.ID,
		Environment:   env.UUID,
	}
	otherNode := nodes.OsqueryNode{
		NodeKey:       "other-node-key",
		UUID:          "OTHER-NODE-UUID",
		EnvironmentID: env.ID,
		Environment:   env.UUID,
	}
	require.NoError(t, db.Create(&consoleNode).Error)
	require.NoError(t, db.Create(&otherNode).Error)
	require.NoError(t, db.Create(&console.Session{
		EnvironmentID: env.ID,
		NodeID:        consoleNode.ID,
		NodeUUID:      consoleNode.UUID,
		Creator:       "alice",
		CWD:           "/",
		Platform:      "linux",
		Active:        true,
	}).Error)

	handler := CreateHandlersTLS(
		WithEnvs(envs),
		WithEnvCache(environments.NewEnvCache(*envs)),
		WithNodes(nodesMgr),
		WithQueries(queryManager),
		WithSettings(settingsMgr),
		WithWriteHandler(NewBatchWriter(100, time.Hour, 10, *nodesMgr)),
		WithOsqueryValues(&config.YAMLConfigurationOsquery{Accelerated: true}),
	)

	consoleResp := queryReadResponse(t, handler, env.UUID, consoleNode.NodeKey)
	require.Equal(t, float64(5), consoleResp["accelerate"])

	otherResp := queryReadResponse(t, handler, env.UUID, otherNode.NodeKey)
	require.NotContains(t, otherResp, "accelerate")
}

func queryReadResponse(t *testing.T, handler *HandlersTLS, envUUID, nodeKey string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]string{"node_key": nodeKey})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/"+envUUID+"/"+environments.DefaultQueryReadPath, bytes.NewReader(body))
	req.SetPathValue("env", envUUID)
	rr := httptest.NewRecorder()

	handler.QueryReadHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}
