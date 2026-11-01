package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Re-enrolling a UUID with environment B's secret must only touch B's row,
// never an earlier row with the same UUID in environment A.
func TestEnrollDoesNotTouchSameUUIDInOtherEnv(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	envB := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "b", Secret: "secret-b", AcceptEnrolls: true}
	require.NoError(t, db.Create(&envB).Error)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	nodesmgr := nodes.CreateNodes(db)
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesmgr), WithTags(tags.CreateTagManager(db)))
	h.AuditLog = audit

	const uuid = "22222222-2222-4222-8222-222222222222"
	nodeA := nodes.OsqueryNode{UUID: uuid, NodeKey: "key-a", Environment: "a", EnvironmentID: 99, Hostname: "host-a"}
	require.NoError(t, nodesmgr.Create(&nodeA))

	for range 2 {
		body, err := json.Marshal(types.EnrollRequest{EnrollSecret: envB.Secret, HostIdentifier: uuid})
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
		r.SetPathValue("env", envB.UUID)
		w := httptest.NewRecorder()
		h.EnrollHandler(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}

	got, err := nodesmgr.GetByUUIDEnv(uuid, 99)
	require.NoError(t, err)
	require.Equal(t, nodeA.ID, got.ID)
	require.Equal(t, "key-a", got.NodeKey)
	require.Equal(t, "a", got.Environment)
	_, err = nodesmgr.GetByUUIDEnv(uuid, envB.ID)
	require.NoError(t, err, "B gets its own row")

	require.NoError(t, nodesmgr.ArchiveDeleteByUUIDEnv(uuid, "b"))
	_, err = nodesmgr.GetByUUIDEnv(uuid, 99)
	require.NoError(t, err, "deleting B's node leaves A's")
}
