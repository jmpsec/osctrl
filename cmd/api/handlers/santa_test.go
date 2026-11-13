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
	return santaDoURL(h, method, "/x", user, body, path)
}

func santaDoURL(h http.HandlerFunc, method, url, user, body string, path map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
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
		"rule create": {h.SantaRuleCreateHandler, "POST"}, "rule update": {h.SantaRuleUpdateHandler, "PUT"}, "rule delete": {h.SantaRuleDeleteHandler, "DELETE"},
		"modes": {h.SantaModeOverridesHandler, "GET"}, "mode set": {h.SantaModeOverrideSetHandler, "PUT"},
		"mode delete": {h.SantaModeOverrideDeleteHandler, "DELETE"}, "rules import": {h.SantaRulesImportHandler, "POST"},
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

func TestSantaConfigPutRemovableMedia(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	tests := []struct {
		name, body string
		code       int
		want       []string
	}{
		{"legacy block_usb_mount", `{"client_mode":"MONITOR","block_usb_mount":true}`, http.StatusOK,
			[]string{`"removable_media":"BLOCK"`, `"block_usb_mount":true`}},
		{"default allow", `{"client_mode":"MONITOR"}`, http.StatusOK,
			[]string{`"removable_media":"ALLOW"`, `"block_usb_mount":false`, `"encrypted_removable_media":""`}},
		{"remount", `{"client_mode":"MONITOR","removable_media":"REMOUNT","removable_media_flags":["RDONLY","noexec"],"encrypted_removable_media":"BLOCK"}`,
			http.StatusOK, []string{`"removable_media_flags":["rdonly","noexec"]`, `"encrypted_removable_media":"BLOCK"`}},
		{"explicit policy wins over legacy flag", `{"client_mode":"MONITOR","removable_media":"ALLOW","block_usb_mount":true}`,
			http.StatusOK, []string{`"removable_media":"ALLOW"`}},
		{"unknown flag", `{"client_mode":"MONITOR","removable_media":"REMOUNT","removable_media_flags":["rw"]}`, http.StatusBadRequest, nil},
		{"remount without flags", `{"client_mode":"MONITOR","removable_media":"REMOUNT"}`, http.StatusBadRequest, nil},
		{"unknown encrypted action", `{"client_mode":"MONITOR","encrypted_removable_media":"DENY"}`, http.StatusBadRequest, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := santaDo(h.SantaConfigPutHandler, "PUT", "alice", tt.body, p)
			require.Equal(t, tt.code, rr.Code, rr.Body.String())
			for _, s := range tt.want {
				require.Contains(t, rr.Body.String(), s)
			}
		})
	}
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

func TestSantaUpdateRule(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	rr := santaDo(h.SantaRuleCreateHandler, "POST", "alice", validRule, p)
	require.Equal(t, http.StatusCreated, rr.Code)
	var rule santa.Rule
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rule))
	require.Equal(t, http.StatusCreated, santaDo(h.SantaRuleCreateHandler, "POST", "alice",
		`{"identifier":"ABCDE12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, p).Code)
	pid := map[string]string{"env": envA.Name, "id": strconv.Itoa(int(rule.ID))}

	rr = santaDo(h.SantaRuleUpdateHandler, "PUT", "alice",
		`{"identifier":"eqhxz8m8av","rule_type":"TEAMID","policy":"BLOCKLIST","custom_msg":"no","scope":"env","created_by":"mallory"}`, pid)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var got santa.Rule
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, rule.ID, got.ID)
	require.Equal(t, "EQHXZ8M8AV", got.Identifier)
	require.Equal(t, "BLOCKLIST", got.Policy)
	require.Equal(t, "alice", got.CreatedBy)
	require.Equal(t, envA.ID, got.EnvironmentID)

	cases := map[string]struct {
		body string
		path map[string]string
		code int
	}{
		"duplicate":  {`{"identifier":"ABCDE12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, pid, http.StatusConflict},
		"invalid":    {`{"identifier":"SHORT","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, pid, http.StatusBadRequest},
		"bad json":   {`{`, pid, http.StatusBadRequest},
		"bad id":     {validRule, map[string]string{"env": envA.Name, "id": "x"}, http.StatusBadRequest},
		"missing id": {validRule, map[string]string{"env": envA.Name, "id": "9999"}, http.StatusNotFound},
		"other env":  {validRule, map[string]string{"env": envB.Name, "id": strconv.Itoa(int(rule.ID))}, http.StatusForbidden},
	}
	for name, tc := range cases {
		require.Equal(t, tc.code, santaDo(h.SantaRuleUpdateHandler, "PUT", "alice", tc.body, tc.path).Code, name)
	}

	// A rule in env B is not reachable through env A.
	ruleB := santa.Rule{EnvironmentID: envB.ID, Identifier: "EQHXZ8M8AV", RuleType: "TEAMID", Policy: "ALLOWLIST", Scope: "env"}
	require.NoError(t, db.Create(&ruleB).Error)
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaRuleUpdateHandler, "PUT", "alice", validRule,
		map[string]string{"env": envA.Name, "id": strconv.Itoa(int(ruleB.ID))}).Code)

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	require.Contains(t, strings.Join(lines, "\n"),
		"santa: update rule "+strconv.Itoa(int(rule.ID))+" TEAMID EQHXZ8M8AV ALLOWLIST scope=env -> TEAMID EQHXZ8M8AV BLOCKLIST scope=env")
}

func TestSantaRulesImport(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	require.Equal(t, http.StatusCreated, santaDo(h.SantaRuleCreateHandler, "POST", "alice", validRule, p).Code)
	count := func(env uint) (n int64) {
		require.NoError(t, db.Model(&santa.Rule{}).Where("environment_id = ?", env).Count(&n).Error)
		return n
	}
	do := func(url, body string) (int, santa.ImportResult) {
		rr := santaDoURL(h.SantaRulesImportHandler, "POST", url, "alice", body, p)
		var res santa.ImportResult
		if rr.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &res))
		}
		return rr.Code, res
	}

	for name, body := range map[string]string{"bad json": `[`, "not a list": validRule, "too large": `["` + strings.Repeat("a", santaImportMaxBody) + `"]`} {
		code, _ := do("/x", body)
		require.Equal(t, http.StatusBadRequest, code, name)
	}

	// body-supplied id, environment_id and created_by are ignored
	fresh := `{"id":99,"environment_id":` + strconv.Itoa(int(envB.ID)) + `,"created_by":"mallory","identifier":"ABCDE12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`
	conflict := `{"identifier":"EQHXZ8M8AV","rule_type":"TEAMID","policy":"BLOCKLIST","scope":"env"}`

	// a conflicting rule is reported and blocks the whole import
	code, res := do("/x", `[`+fresh+`,`+conflict+`]`)
	require.Equal(t, http.StatusOK, code)
	require.False(t, res.Applied)
	require.Equal(t, 1, res.New)
	require.Len(t, res.Conflicts, 1)
	require.EqualValues(t, 1, count(envA.ID))

	code, res = do("/x?dry_run=true", `[`+fresh+`,`+validRule+`]`)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, santa.ImportResult{New: 1, Duplicate: 1, Conflicts: []santa.ImportIssue{}, Invalid: []santa.ImportIssue{}}, res)
	require.EqualValues(t, 1, count(envA.ID))

	code, res = do("/x", `[`+fresh+`,`+validRule+`]`)
	require.Equal(t, http.StatusOK, code)
	require.True(t, res.Applied)
	require.EqualValues(t, 2, count(envA.ID))
	require.EqualValues(t, 0, count(envB.ID))
	var stored santa.Rule
	require.NoError(t, db.Where("identifier = ?", "ABCDE12345").First(&stored).Error)
	require.Equal(t, "alice", stored.CreatedBy)
	require.NotEqualValues(t, 99, stored.ID)

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Where("line LIKE ?", "%santa: import%").Pluck("line", &lines).Error)
	require.Len(t, lines, 1, "one audit line, only for the applied import")
	require.Contains(t, lines[0], "santa: import rules new=1 duplicate=1")
}

func TestSantaModeOverrides(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	const node = "11111111-2222-3333-4444-555555555555"

	for name, body := range map[string]string{
		"bad json": `{`, "env scope": `{"scope":"env","client_mode":"LOCKDOWN"}`,
		"bad mode":  `{"scope":"tag","scope_value":"pilot","client_mode":"OFF"}`,
		"empty tag": `{"scope":"tag","client_mode":"LOCKDOWN"}`,
		"bad uuid":  `{"scope":"node","scope_value":"nope","client_mode":"LOCKDOWN"}`,
	} {
		require.Equal(t, http.StatusBadRequest, santaDo(h.SantaModeOverrideSetHandler, "PUT", "alice", body, p).Code, name)
	}

	// body-supplied environment_id and created_by are ignored; the node UUID is uppercased
	rr := santaDo(h.SantaModeOverrideSetHandler, "PUT", "alice",
		`{"scope":"node","scope_value":"`+node+`","client_mode":"LOCKDOWN","created_by":"mallory","environment_id":`+strconv.Itoa(int(envB.ID))+`}`, p)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var o santa.ModeOverride
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &o))
	require.Equal(t, envA.ID, o.EnvironmentID)
	require.Equal(t, "alice", o.CreatedBy)
	require.Equal(t, strings.ToUpper(node), o.ScopeValue)

	// setting the same node again replaces the mode instead of adding a row
	rr = santaDo(h.SantaModeOverrideSetHandler, "PUT", "alice", `{"scope":"node","scope_value":"`+node+`","client_mode":"MONITOR"}`, p)
	require.Equal(t, http.StatusOK, rr.Code)
	var again santa.ModeOverride
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &again))
	require.Equal(t, o.ID, again.ID)
	require.Equal(t, "MONITOR", again.ClientMode)
	rr = santaDo(h.SantaModeOverridesHandler, "GET", "alice", "", p)
	var list []santa.ModeOverride
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)

	// an override in env B is not reachable through env A
	inB := santa.ModeOverride{EnvironmentID: envB.ID, Scope: "tag", ScopeValue: "pilot", ClientMode: "LOCKDOWN"}
	require.NoError(t, db.Create(&inB).Error)
	del := func(id string) int {
		return santaDo(h.SantaModeOverrideDeleteHandler, "DELETE", "alice", "", map[string]string{"env": envA.Name, "id": id}).Code
	}
	require.Equal(t, http.StatusNotFound, del(strconv.Itoa(int(inB.ID))))
	require.Equal(t, http.StatusBadRequest, del("x"))
	require.Equal(t, http.StatusNoContent, del(strconv.Itoa(int(o.ID))))
	var n int64
	require.NoError(t, db.Model(&santa.ModeOverride{}).Count(&n).Error)
	require.EqualValues(t, 1, n)

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	all := strings.Join(lines, "\n")
	require.Contains(t, all, "santa: set mode override LOCKDOWN scope=node scope_value="+strings.ToUpper(node))
	require.Contains(t, all, "santa: delete mode override MONITOR scope=node scope_value="+strings.ToUpper(node))
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
