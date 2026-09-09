package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestQueryReadDatabaseFailureIsRetryable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "test"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{NodeKey: "key", UUID: "NODE", EnvironmentID: env.ID}
	require.NoError(t, db.Create(&node).Error)
	writer := &batchWriter{events: make(chan lastSeenUpdate, 1)}
	// No query tables: the authenticated request reaches a failing SQL read.
	h := CreateHandlersTLS(WithEnvCache(environments.NewEnvCache(*envs)), WithNodes(nodesRepo),
		WithQueries(&queries.Queries{DB: db}), WithWriteHandler(writer))
	req := httptest.NewRequest(http.MethodPost, "/"+env.UUID+"/read", bytes.NewBufferString(`{"node_key":"key"}`))
	req.SetPathValue("env", env.UUID)
	w := httptest.NewRecorder()
	h.QueryReadHandler(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.NotContains(t, w.Body.String(), "node_queries", "do not expose SQL details")
	require.Len(t, writer.events, 1, "an authenticated check-in still updates liveness")
}
