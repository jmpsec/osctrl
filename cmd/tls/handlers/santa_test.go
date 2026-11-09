package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"buf.build/gen/go/northpolesec/protos/protocolbuffers/go/syncv2"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	santaEnvUUID   = "11111111-1111-4111-8111-111111111111"
	santaEnv2UUID  = "33333333-3333-4333-8333-333333333333"
	santaMachineID = "22222222-2222-4222-8222-222222222222"
)

type santaFixture struct {
	h     *HandlersTLS
	db    *gorm.DB
	token string
	env   environments.TLSEnvironment
}

func newSantaFixture(t *testing.T) *santaFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: santaEnvUUID, Name: "env"}
	env2 := environments.TLSEnvironment{UUID: santaEnv2UUID, Name: "env2"}
	require.NoError(t, db.Create(&env).Error)
	require.NoError(t, db.Create(&env2).Error)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	mgr, err := santa.NewManager(db)
	require.NoError(t, err)
	token, err := mgr.RotateToken(env.ID)
	require.NoError(t, err)
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodes.CreateNodes(db)), WithTags(tags.CreateTagManager(db)), WithSanta(mgr))
	h.AuditLog = audit
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: strings.ToUpper(santaMachineID), EnvironmentID: env.ID}).Error)
	return &santaFixture{h: h, db: db, token: token, env: env}
}

func (f *santaFixture) post(envUUID, stage, machine, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("X-Osctrl-Santa-Token", token)
	}
	r.SetPathValue("env", envUUID)
	r.SetPathValue("stage", stage)
	r.SetPathValue("machineid", machine)
	w := httptest.NewRecorder()
	f.h.SantaHandler(w, r)
	return w
}

func (f *santaFixture) failures(t *testing.T) int64 {
	var n int64
	require.NoError(t, f.db.Model(&auditlog.AuditLog{}).Where("line LIKE ?", "failed santa%").Count(&n).Error)
	return n
}

func TestSantaRejectsMissingToken(t *testing.T) {
	f := newSantaFixture(t)
	w := f.post(santaEnvUUID, "preflight", santaMachineID, "", []byte(`{}`))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Body.String())
	require.EqualValues(t, 1, f.failures(t))
}

func TestSantaRejectsWrongToken(t *testing.T) {
	f := newSantaFixture(t)
	w := f.post(santaEnvUUID, "preflight", santaMachineID, "nope", []byte(`{}`))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.EqualValues(t, 1, f.failures(t))
}

func TestSantaRejectsBadEnvUUID(t *testing.T) {
	f := newSantaFixture(t)
	require.Equal(t, http.StatusBadRequest, f.post("not-a-uuid", "preflight", santaMachineID, f.token, []byte(`{}`)).Code)
	require.Equal(t, http.StatusBadRequest, f.post(santaEnvUUID, "preflight", "bad", f.token, []byte(`{}`)).Code)
}

func TestSantaUnknownEnvIsForbidden(t *testing.T) {
	f := newSantaFixture(t)
	w := f.post("44444444-4444-4444-8444-444444444444", "preflight", santaMachineID, f.token, []byte(`{}`))
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSantaRejectsUnknownMachine(t *testing.T) {
	f := newSantaFixture(t)
	w := f.post(santaEnvUUID, "preflight", "55555555-5555-4555-8555-555555555555", f.token, []byte(`{}`))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.EqualValues(t, 1, f.failures(t))
}

func TestSantaRejectsNodeFromOtherEnv(t *testing.T) {
	f := newSantaFixture(t)
	var env2 environments.TLSEnvironment
	require.NoError(t, f.db.Where("uuid = ?", santaEnv2UUID).First(&env2).Error)
	other := "66666666-6666-4666-8666-666666666666"
	require.NoError(t, f.db.Create(&nodes.OsqueryNode{UUID: strings.ToUpper(other), EnvironmentID: env2.ID}).Error)
	w := f.post(santaEnvUUID, "preflight", other, f.token, []byte(`{}`))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.EqualValues(t, 1, f.failures(t))
}

func TestSantaUnknownStage(t *testing.T) {
	f := newSantaFixture(t)
	require.Equal(t, http.StatusNotFound, f.post(santaEnvUUID, "bogus", santaMachineID, f.token, []byte(`{}`)).Code)
}

func TestSantaMalformedBodyAndNoPreflight(t *testing.T) {
	f := newSantaFixture(t)
	require.Equal(t, http.StatusBadRequest, f.post(santaEnvUUID, "preflight", santaMachineID, f.token, []byte(`{`)).Code)
	require.Equal(t, http.StatusBadRequest, f.post(santaEnvUUID, "postflight", santaMachineID, f.token, []byte(`{}`)).Code)
}

func TestSantaFullSyncJSON(t *testing.T) {
	f := newSantaFixture(t)
	mgr := f.h.Santa
	id := strings.Repeat("ab", 32)
	require.NoError(t, mgr.CreateRule(&santa.Rule{EnvironmentID: f.env.ID, RuleType: "BINARY", Identifier: id, Policy: "BLOCKLIST", Scope: "env"}))
	require.NoError(t, mgr.CreateRule(&santa.Rule{EnvironmentID: f.env.ID + 1, RuleType: "BINARY", Identifier: strings.Repeat("cd", 32), Policy: "BLOCKLIST", Scope: "env"}))

	w := f.post(santaEnvUUID, "preflight", santaMachineID, f.token, []byte(`{"hostname":"h"}`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var pre syncv2.PreflightResponse
	require.NoError(t, protojson.Unmarshal(w.Body.Bytes(), &pre))
	require.Equal(t, syncv2.SyncType_CLEAN_RULES, pre.GetSyncType())

	w = f.post(santaEnvUUID, "ruledownload", santaMachineID, f.token, []byte(`{}`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var rd syncv2.RuleDownloadResponse
	require.NoError(t, protojson.Unmarshal(w.Body.Bytes(), &rd))
	require.Len(t, rd.GetRules(), 1)
	require.Equal(t, strings.ToUpper(id), strings.ToUpper(rd.GetRules()[0].GetIdentifier()))

	w = f.post(santaEnvUUID, "postflight", santaMachineID, f.token, []byte(`{}`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestSantaAuditCapPerEnvironment(t *testing.T) {
	f := newSantaFixture(t)
	dropped := santaAuthAuditDropped.WithLabelValues(f.env.Name)
	before := metricValue(t, dropped)
	for i := 0; i < santaAuditPerHour+1; i++ {
		require.Equal(t, http.StatusForbidden, f.post(santaEnvUUID, "preflight", santaMachineID, "wrong", []byte(`{}`)).Code)
	}
	require.EqualValues(t, santaAuditPerHour, f.failures(t))
	require.Equal(t, before+1, metricValue(t, dropped))
}

func TestSantaOversizedBody(t *testing.T) {
	f := newSantaFixture(t)
	body := bytes.Repeat([]byte(" "), santa.MaxRawBody+1)
	w := f.post(santaEnvUUID, "eventupload", santaMachineID, f.token, body)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.Empty(t, w.Body.String())
}
