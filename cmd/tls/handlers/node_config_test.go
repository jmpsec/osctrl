package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	ncEnvConfig = `{"options":{"a":1}}`
	ncOverride  = `{"options":{"verbose":true}}`
)

type nodeConfigFixture struct {
	db  *gorm.DB
	h   *HandlersTLS
	m   *nodeconfig.Manager
	env environments.TLSEnvironment
}

func newNodeConfigFixture(t *testing.T, envConfig string, withManager bool) *nodeConfigFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Configuration: envConfig}
	require.NoError(t, db.Create(&env).Error)
	for _, n := range []nodes.OsqueryNode{
		{NodeKey: "key-a", UUID: "NODE-A", EnvironmentID: env.ID},
		{NodeKey: "key-b", UUID: "NODE-B", EnvironmentID: env.ID},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	opts := []Option{
		WithEnvCache(environments.NewEnvCache(*envs)),
		WithNodes(nodesRepo),
		WithWriteHandler(&batchWriter{events: make(chan lastSeenUpdate, 8)}),
	}
	f := &nodeConfigFixture{db: db, env: env}
	if withManager {
		f.m, err = nodeconfig.NewManager(db, nil)
		require.NoError(t, err)
		opts = append(opts, WithNodeConfig(f.m))
	}
	f.h = CreateHandlersTLS(opts...)
	return f
}

func (f *nodeConfigFixture) config(t *testing.T, nodeKey string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/"+f.env.UUID+"/config", bytes.NewBufferString(`{"node_key":"`+nodeKey+`"}`))
	r.SetPathValue("env", f.env.UUID)
	w := httptest.NewRecorder()
	f.h.ConfigHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}

func (f *nodeConfigFixture) set(t *testing.T, uuid, cfg string, expires *time.Time) {
	t.Helper()
	_, err := f.m.Set(context.Background(), nodeconfig.Override{NodeUUID: uuid, EnvironmentID: f.env.ID, Config: cfg, ExpiresAt: expires})
	require.NoError(t, err)
}

func TestConfigServesMergedOverride(t *testing.T) {
	f := newNodeConfigFixture(t, ncEnvConfig, true)
	f.set(t, "NODE-A", ncOverride, nil)
	var got struct {
		Options map[string]any `json:"options"`
	}
	require.NoError(t, json.Unmarshal([]byte(f.config(t, "key-a")), &got))
	require.EqualValues(t, 1, got.Options["a"])
	require.Equal(t, true, got.Options["verbose"])
}

func TestConfigOtherNodesUnaffected(t *testing.T) {
	f := newNodeConfigFixture(t, ncEnvConfig, true)
	f.set(t, "NODE-A", ncOverride, nil)
	require.Equal(t, ncEnvConfig, f.config(t, "key-b"))
}

func TestConfigIgnoresExpiredOverride(t *testing.T) {
	f := newNodeConfigFixture(t, ncEnvConfig, true)
	past := time.Now().Add(-time.Hour)
	f.set(t, "NODE-A", ncOverride, &past)
	require.Equal(t, ncEnvConfig, f.config(t, "key-a"))
}

func TestConfigFallsBackOnInvalidStoredOverride(t *testing.T) {
	f := newNodeConfigFixture(t, ncEnvConfig, true)
	require.NoError(t, f.db.Create(&nodeconfig.Override{
		NodeUUID: "NODE-A", EnvironmentID: f.env.ID, Config: `{"options":{"tls_hostname":"evil"}}`,
	}).Error)
	require.Equal(t, ncEnvConfig, f.config(t, "key-a"))
}

func TestConfigFallsBackOnInvalidEnvironmentConfig(t *testing.T) {
	f := newNodeConfigFixture(t, "{", true)
	f.set(t, "NODE-A", ncOverride, nil)
	require.Equal(t, "{", f.config(t, "key-a"))
}

func TestConfigWithoutNodeConfigManager(t *testing.T) {
	f := newNodeConfigFixture(t, ncEnvConfig, false)
	require.Nil(t, f.h.NodeConfig)
	require.Equal(t, ncEnvConfig, f.config(t, "key-a"))
}
