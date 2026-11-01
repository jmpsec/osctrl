package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type switchExporter struct{ fail bool }

func (e *switchExporter) Name() string    { return "test" }
func (e *switchExporter) IsEnabled() bool { return true }
func (e *switchExporter) Close() error    { return nil }
func (e *switchExporter) Export(string, []byte, logging.ExportParams) error {
	if e.fail {
		return errors.New("sink down")
	}
	return nil
}

// A log batch is acknowledged only once stored; a failed sink or a full
// ingestion budget answers with a retryable error instead.
func TestLogHandlerAcknowledgesOnlyStoredBatches(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	nodesmgr := nodes.CreateNodes(db)
	require.NoError(t, nodesmgr.Create(&nodes.OsqueryNode{UUID: "NODE-A", NodeKey: "key-a", EnvironmentID: env.ID, Environment: "env"}))
	sink := &switchExporter{}
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesmgr),
		WithLogs(logging.CreateLoggerTLSWith(map[uint]*logging.MultiExporter{0: logging.NewMultiExporter(sink)}, nodesmgr, nil)))

	post := func() int {
		r := httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{"node_key":"key-a","log_type":"status","data":[{"message":"m","severity":0}]}`))
		r.SetPathValue("env", env.UUID)
		w := httptest.NewRecorder()
		h.LogHandler(w, r)
		return w.Code
	}

	require.Equal(t, http.StatusOK, post())
	sink.fail = true
	require.Equal(t, http.StatusInternalServerError, post())
	sink.fail = false

	require.True(t, logIngest.TryAcquire(logIngestBudget))
	require.Equal(t, http.StatusServiceUnavailable, post())
	logIngest.Release(logIngestBudget)
	require.Equal(t, http.StatusOK, post())
}
