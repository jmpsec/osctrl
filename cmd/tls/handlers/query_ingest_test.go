package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Distributed query results are processed in the background, but only within
// the in-flight byte budget: a request waits for room instead of piling more
// results into memory, and gives up with a retryable 503 if the agent leaves.
func TestQueryWriteWaitsForIngestBudget(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	nodesmgr := nodes.CreateNodes(db)
	require.NoError(t, nodesmgr.Create(&nodes.OsqueryNode{UUID: "NODE-A", NodeKey: "key-a", EnvironmentID: env.ID, Environment: "env"}))
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesmgr),
		WithWriteHandler(NewBatchWriter(10, time.Second, 10, *nodesmgr)),
		WithLogs(logging.CreateLoggerTLSWith(map[uint]*logging.MultiExporter{0: logging.NewMultiExporter(&switchExporter{})}, nodesmgr, nil)))

	post := func(ctx context.Context) int {
		r := httptest.NewRequest(http.MethodPost, "/write", strings.NewReader(`{"node_key":"key-a","queries":{},"statuses":{}}`)).WithContext(ctx)
		r.SetPathValue("env", env.UUID)
		w := httptest.NewRecorder()
		h.QueryWriteHandler(w, r)
		return w.Code
	}

	require.True(t, queryIngest.TryAcquire(queryIngestBudget))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.Equal(t, http.StatusServiceUnavailable, post(ctx))
	queryIngest.Release(queryIngestBudget)

	require.Equal(t, http.StatusOK, post(context.Background()))
	// The background processing returns its share of the budget.
	require.Eventually(t, func() bool {
		if !queryIngest.TryAcquire(queryIngestBudget) {
			return false
		}
		queryIngest.Release(queryIngestBudget)
		return true
	}, time.Second, 10*time.Millisecond)
}
