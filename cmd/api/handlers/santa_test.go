package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// alice is env-A admin; carol only has UserLevel on env-A.
func setupSantaHandlers(t *testing.T) (*HandlersApi, *gorm.DB, environments.TLSEnvironment, environments.TLSEnvironment) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	mgr, err := santa.NewManager(db)
	require.NoError(t, err)

	envA := environments.TLSEnvironment{UUID: "env-a", Name: "a"}
	envB := environments.TLSEnvironment{UUID: "env-b", Name: "b"}
	require.NoError(t, db.Create(&envA).Error)
	require.NoError(t, db.Create(&envB).Error)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "carol"}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username: "alice", AccessType: int(users.AdminLevel), AccessValue: true, Environment: envA.UUID, EnvironmentID: envA.ID,
	}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username: "carol", AccessType: int(users.UserLevel), AccessValue: true, Environment: envA.UUID, EnvironmentID: envA.ID,
	}))
	h := CreateHandlersApi(WithDB(db), WithEnvs(envs), WithUsers(userManager), WithAuditLog(auditLog), WithSanta(mgr))
	return h, db, envA, envB
}

func santaDo(h http.HandlerFunc, method, user, body string, path map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/x", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range path {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

const validRule = `{"identifier":"EQHXZ8M8AV","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`

func TestSantaRoutesRequireEnvAdmin(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name, "id": "1"}
	routes := map[string]struct {
		fn     http.HandlerFunc
		method string
	}{
		"config get": {h.SantaConfigGetHandler, "GET"}, "config put": {h.SantaConfigPutHandler, "PUT"},
		"token": {h.SantaTokenHandler, "POST"}, "rules": {h.SantaRulesHandler, "GET"},
		"rule create": {h.SantaRuleCreateHandler, "POST"}, "rule delete": {h.SantaRuleDeleteHandler, "DELETE"},
		"machines": {h.SantaMachinesHandler, "GET"}, "events": {h.SantaEventsHandler, "GET"},
	}
	for name, rt := range routes {
		require.Equal(t, http.StatusForbidden, santaDo(rt.fn, rt.method, "carol", validRule, p).Code, name)
	}
}

func TestSantaDisabledIs503(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	h.Santa = nil
	rr := santaDo(h.SantaRulesHandler, "GET", "alice", "", map[string]string{"env": envA.Name})
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestSantaConfigGetNeverReturnsToken(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	rr := santaDo(h.SantaTokenHandler, "POST", "alice", "", p)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var tok SantaTokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	require.NotEmpty(t, tok.Token)
	require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))

	rr = santaDo(h.SantaConfigGetHandler, "GET", "alice", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	var m map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &m))
	require.Equal(t, true, m["token_set"])
	require.Equal(t, "MONITOR", m["client_mode"]) // snake_case keys round-trip with PUT
	require.NotContains(t, m, "token")
	require.NotContains(t, m, "token_hash")
	require.NotContains(t, strings.ToLower(rr.Body.String()), "hash")
	require.NotContains(t, rr.Body.String(), tok.Token)
}

func TestSantaConfigPut(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{"client_mode":"NOPE"}`, p).Code)
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{`, p).Code)
	rr := santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{"client_mode":"LOCKDOWN","batch_size":7}`, p)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), `"LOCKDOWN"`)
}

func TestSantaCreateRuleValidation(t *testing.T) {
	h, _, envA, envB := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaRuleCreateHandler, "POST", "alice",
		`{"identifier":"SHORT","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, p).Code)
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaRuleCreateHandler, "POST", "alice", `{`, p).Code)

	// body-supplied environment_id and created_by must be ignored
	body := `{"identifier":"EQHXZ8M8AV","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env","environment_id":` +
		strconv.Itoa(int(envB.ID)) + `,"created_by":"mallory"}`
	rr := santaDo(h.SantaRuleCreateHandler, "POST", "alice", body, p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var rule santa.Rule
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rule))
	require.Equal(t, envA.ID, rule.EnvironmentID)
	require.Equal(t, "alice", rule.CreatedBy)

	require.Equal(t, http.StatusConflict, santaDo(h.SantaRuleCreateHandler, "POST", "alice", validRule, p).Code)
}

func TestSantaDeleteRuleCrossEnv(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	rule := santa.Rule{EnvironmentID: envB.ID, Identifier: "EQHXZ8M8AV", RuleType: "TEAMID", Policy: "ALLOWLIST", Scope: "env"}
	require.NoError(t, db.Create(&rule).Error)
	id := strconv.Itoa(int(rule.ID))
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaRuleDeleteHandler, "DELETE", "alice", "", map[string]string{"env": envA.Name, "id": id}).Code)
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaRuleDeleteHandler, "DELETE", "alice", "", map[string]string{"env": envA.Name, "id": "x"}).Code)
	var n int64
	require.NoError(t, db.Model(&santa.Rule{}).Count(&n).Error)
	require.EqualValues(t, 1, n)
}

func TestSantaMutationsAudited(t *testing.T) {
	h, db, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	rr := santaDo(h.SantaRuleCreateHandler, "POST", "alice", validRule, p)
	require.Equal(t, http.StatusCreated, rr.Code)
	var rule santa.Rule
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rule))
	rr = santaDo(h.SantaTokenHandler, "POST", "alice", "", p)
	var tok SantaTokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{"client_mode":"MONITOR"}`, p).Code)
	require.Equal(t, http.StatusNoContent, santaDo(h.SantaRuleDeleteHandler, "DELETE", "alice", "",
		map[string]string{"env": envA.Name, "id": strconv.Itoa(int(rule.ID))}).Code)

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	all := strings.Join(lines, "\n")
	for _, want := range []string{"santa: create rule", "santa: delete rule", "TEAMID EQHXZ8M8AV ALLOWLIST scope=env", "santa: rotate token", "santa: update config"} {
		require.Contains(t, all, want)
	}
	require.NotContains(t, all, tok.Token)
}

func TestFeaturesSanta(t *testing.T) {
	h, _, _, _ := setupSantaHandlers(t)
	get := func() map[string]any {
		rr := httptest.NewRecorder()
		h.FeaturesHandler(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		var m map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &m))
		return m
	}
	require.Equal(t, true, get()["santa"])
	h.Santa = nil
	require.Equal(t, false, get()["santa"])
}
