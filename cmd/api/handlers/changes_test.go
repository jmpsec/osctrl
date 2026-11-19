package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/changes"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// TestSantaSecondAdmin: alice and bob are env-A admins, carol is a user.
func TestSantaSecondAdmin(t *testing.T) {
	h, db, envA, _ := setupSantaHandlers(t)
	cm, err := changes.NewManager(db)
	require.NoError(t, err)
	h.Changes = cm
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "bob"}))
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{
		Username: "bob", AccessType: int(users.AdminLevel), AccessValue: true, Environment: envA.UUID, EnvironmentID: envA.ID,
	}))
	p := map[string]string{"env": envA.Name}
	held := func(body []byte) changes.Change {
		t.Helper()
		var res PendingChangeResponse
		require.NoError(t, json.Unmarshal(body, &res))
		return res.PendingChange
	}
	decide := func(user string, id uint, decision string) int {
		return santaDo(h.ChangeDecideHandler, "POST", user, `{"decision":"`+decision+`"}`,
			map[string]string{"env": envA.Name, "id": strconv.Itoa(int(id))}).Code
	}
	mode := func() string {
		cfg, err := h.Santa.Config(envA.ID)
		require.NoError(t, err)
		return cfg.ClientMode
	}

	// An environment-wide allow rule made before the setting, edited below.
	rr := santaDo(h.SantaRuleCreateHandler, "POST", "alice", validRule, p)
	require.Equal(t, http.StatusCreated, rr.Code)
	var envRule struct{ ID uint }
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envRule))
	rp := map[string]string{"env": envA.Name, "id": strconv.Itoa(int(envRule.ID))}

	// Turning the setting on is not held.
	on := `{"client_mode":"LOCKDOWN","require_second_admin":true}`
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice", on, p).Code)

	// Switching to MONITOR is held, and sending it again returns the same change.
	monitor := `{"client_mode":"MONITOR","require_second_admin":true}`
	rr = santaDo(h.SantaConfigPutHandler, "PUT", "alice", monitor, p)
	require.Equal(t, http.StatusAccepted, rr.Code)
	c := held(rr.Body.Bytes())
	require.Equal(t, changes.StatusPending, c.Status)
	require.Contains(t, c.Action, "client_mode=MONITOR")
	rr = santaDo(h.SantaConfigPutHandler, "PUT", "alice", monitor, p)
	require.Equal(t, http.StatusAccepted, rr.Code)
	require.Equal(t, c.ID, held(rr.Body.Bytes()).ID)
	require.Equal(t, "LOCKDOWN", mode())

	// Only another admin of the environment approves.
	require.Equal(t, http.StatusForbidden, decide("alice", c.ID, "approve"))
	require.Equal(t, http.StatusForbidden, decide("carol", c.ID, "approve"))
	require.Equal(t, http.StatusForbidden, santaDo(h.ChangesHandler, "GET", "carol", "", p).Code)
	rr = santaDo(h.ChangesHandler, "GET", "bob", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	var list []ChangeView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)
	require.False(t, list[0].Mine)
	require.Equal(t, monitor, list[0].Body)
	require.Equal(t, http.StatusOK, decide("bob", c.ID, "approve"))
	require.Equal(t, http.StatusConflict, decide("bob", c.ID, "deny"))

	// The requester applies it by sending it again, once.
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice", monitor, p).Code)
	require.Equal(t, "MONITOR", mode())
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice", on, p).Code)
	require.Equal(t, http.StatusAccepted, santaDo(h.SantaConfigPutHandler, "PUT", "alice", monitor, p).Code)

	held202 := []struct {
		name   string
		fn     http.HandlerFunc
		method string
		body   string
		path   map[string]string
	}{
		{"rotate token", h.SantaTokenHandler, "POST", "", p},
		{"env allow rule", h.SantaRuleCreateHandler, "POST", `{"identifier":"ABCDE12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, p},
		{"env CEL rule", h.SantaRuleCreateHandler, "POST", `{"identifier":"ABCDE12346","rule_type":"TEAMID","policy":"CEL","cel_expr":"true","scope":"env"}`, p},
		{"rule allows something else", h.SantaRuleUpdateHandler, "PUT", `{"identifier":"ABCDE12347","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, rp},
		{"import with env allow", h.SantaRulesImportHandler, "POST", `[{"identifier":"ABCDE12348","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}]`, p},
		{"MONITOR override", h.SantaModeOverrideSetHandler, "PUT", `{"scope":"tag","scope_value":"pilot","client_mode":"MONITOR"}`, p},
		{"turn the setting off", h.SantaConfigPutHandler, "PUT", `{"client_mode":"LOCKDOWN"}`, p},
		{"allowed path regex", h.SantaConfigPutHandler, "PUT", `{"client_mode":"LOCKDOWN","require_second_admin":true,"allowed_path_regex":"^/tmp/"}`, p},
		{"approver user", h.SantaConfigPutHandler, "PUT", `{"client_mode":"LOCKDOWN","require_second_admin":true,"approver_users":["carol"]}`, p},
		{"approver group", h.SantaConfigPutHandler, "PUT", `{"client_mode":"LOCKDOWN","require_second_admin":true,"approver_groups":["helpdesk"]}`, p},
	}
	for _, tt := range held202 {
		require.Equal(t, http.StatusAccepted, santaDo(tt.fn, tt.method, "alice", tt.body, tt.path).Code, tt.name)
	}
	notHeld := []struct {
		name   string
		fn     http.HandlerFunc
		method string
		body   string
		path   map[string]string
		code   int
	}{
		{"env block rule", h.SantaRuleCreateHandler, "POST", `{"identifier":"BBCDE12345","rule_type":"TEAMID","policy":"BLOCKLIST","scope":"env"}`, p, http.StatusCreated},
		{"tag allow rule", h.SantaRuleCreateHandler, "POST", `{"identifier":"CBCDE12345","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"tag","scope_value":"pilot"}`, p, http.StatusCreated},
		{"message of an env allow rule", h.SantaRuleUpdateHandler, "PUT", `{"identifier":"EQHXZ8M8AV","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env","custom_msg":"hi"}`, rp, http.StatusOK},
		{"invalid rule is rejected, not held", h.SantaRuleCreateHandler, "POST", `{"identifier":"x","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}`, p, http.StatusBadRequest},
		{"import dry run", h.SantaRulesImportHandler, "POST", `[{"identifier":"ABCDE12348","rule_type":"TEAMID","policy":"ALLOWLIST","scope":"env"}]`, p, http.StatusOK},
		{"LOCKDOWN override", h.SantaModeOverrideSetHandler, "PUT", `{"scope":"tag","scope_value":"pilot","client_mode":"LOCKDOWN"}`, p, http.StatusOK},
	}
	for _, tt := range notHeld {
		url := "/x"
		if tt.name == "import dry run" {
			url += "?dry_run=true"
		}
		require.Equal(t, tt.code, santaDoURL(tt.fn, tt.method, url, "alice", tt.body, tt.path).Code, tt.name)
	}

	// The requester can withdraw their own change.
	rr = santaDo(h.SantaTokenHandler, "POST", "alice", "", p)
	tok := held(rr.Body.Bytes())
	require.Equal(t, http.StatusOK, decide("alice", tok.ID, "deny"))

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"change: request " + strconv.Itoa(int(c.ID)) + " santa: update config client_mode=MONITOR",
		"change: approve " + strconv.Itoa(int(c.ID)),
		"change: apply " + strconv.Itoa(int(c.ID)),
		"approved_by=bob",
		"change: deny " + strconv.Itoa(int(tok.ID)),
	} {
		require.Contains(t, all, want)
	}
}
