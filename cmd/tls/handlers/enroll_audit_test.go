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

func TestEnrollAuditsOnlyPersistedSuccess(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Secret: "enrollment-test-secret", AcceptEnrolls: true}
	require.NoError(t, db.Create(&env).Error)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodes.CreateNodes(db)), WithTags(tags.CreateTagManager(db)))
	h.AuditLog = audit
	enroll := func(secret string) *httptest.ResponseRecorder {
		body, err := json.Marshal(types.EnrollRequest{EnrollSecret: secret, HostIdentifier: "22222222-2222-4222-8222-222222222222"})
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
		r.SetPathValue("env", env.UUID)
		w := httptest.NewRecorder()
		h.EnrollHandler(w, r)
		return w
	}
	countEnrolls := func() int64 {
		var count int64
		require.NoError(t, db.Model(&auditlog.AuditLog{}).Where("log_type = ?", auditlog.LogTypeEnroll).Count(&count).Error)
		return count
	}
	require.Equal(t, http.StatusForbidden, enroll("wrong").Code)
	require.Zero(t, countEnrolls())
	for i := 1; i <= 2; i++ {
		w := enroll(env.Secret)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var result types.EnrollResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.False(t, result.NodeInvalid)
		require.EqualValues(t, i, countEnrolls(), "re-enrollment is also a successful enrollment")
	}
	require.NoError(t, db.Migrator().DropTable(&nodes.OsqueryNode{}))
	w := enroll(env.Secret)
	var result types.EnrollResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.True(t, result.NodeInvalid)
	require.EqualValues(t, 2, countEnrolls(), "a failed database write must not count as enrollment")
}
