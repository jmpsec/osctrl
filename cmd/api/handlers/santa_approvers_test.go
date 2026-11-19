package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// erin is an approver by name and frank by group; neither has an environment
// permission. carol is a plain environment user, dave a requester.
func TestSantaApprovers(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "frank"}))
	require.NoError(t, h.Santa.SetUserGroups("frank", []string{"helpdesk"}))
	access := func(user string) SantaAccessResponse {
		t.Helper()
		rr := santaDo(h.SantaAccessHandler, "GET", user, "", p)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var a SantaAccessResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &a))
		return a
	}
	require.Equal(t, SantaAccessResponse{Admin: true}, access("alice"))
	require.Equal(t, SantaAccessResponse{}, access("erin"))

	put := func(user, approvers string) int {
		return santaDo(h.SantaConfigPutHandler, "PUT", user,
			`{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com","approver_users":`+approvers+`,"approver_groups":["helpdesk"]}`, p).Code
	}
	require.Equal(t, http.StatusBadRequest, put("alice", `["nobody"]`))
	require.Equal(t, http.StatusForbidden, put("erin", `["erin"]`))
	rr := santaDo(h.SantaConfigPutHandler, "PUT", "alice",
		`{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com","approver_users":["erin"," erin "],"approver_groups":["helpdesk"]}`, p)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var saved SantaConfigResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &saved))
	require.Equal(t, []string{"erin"}, saved.ApproverUsers)
	require.Equal(t, []string{"helpdesk"}, saved.ApproverGroups)

	require.Equal(t, SantaAccessResponse{Approver: true}, access("erin"))
	require.Equal(t, SantaAccessResponse{Approver: true}, access("frank"))
	require.Equal(t, SantaAccessResponse{}, access("carol"))
	require.Equal(t, SantaAccessResponse{}, access("dave"))
	// Approvers of env A are nothing in env B.
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestsHandler, "GET", "erin", "", map[string]string{"env": "env-b"}).Code)

	// The rest of the Santa page stays admin-only.
	for _, a := range []struct {
		name   string
		fn     http.HandlerFunc
		method string
		body   string
	}{
		{"config", h.SantaConfigGetHandler, "GET", ""},
		{"rules", h.SantaRulesHandler, "GET", ""},
		{"rule create", h.SantaRuleCreateHandler, "POST", validRule},
		{"token", h.SantaTokenHandler, "POST", ""},
		{"machines", h.SantaMachinesHandler, "GET", ""},
		{"events", h.SantaEventsHandler, "GET", ""},
	} {
		require.Equal(t, http.StatusForbidden, santaDo(a.fn, a.method, "erin", a.body, p).Code, a.name)
	}

	rr = santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "I need this tool"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	one := map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}

	for _, who := range []string{"erin", "frank"} {
		require.Equal(t, http.StatusOK, santaDo(h.SantaRequestsHandler, "GET", who, "", p).Code, who)
		require.Equal(t, http.StatusOK, santaDo(h.SantaRequestGetHandler, "GET", who, "", one).Code, who)
	}
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestsHandler, "GET", "carol", "", p).Code)
	require.Equal(t, http.StatusForbidden,
		santaDo(h.SantaRequestDecideHandler, "POST", "carol", `{"decision":"approve","scope":"node"}`, one).Code)
	// Only admins override a risk check.
	require.Equal(t, http.StatusForbidden,
		santaDo(h.SantaRequestDecideHandler, "POST", "frank", `{"decision":"approve","scope":"node","override":true,"reason":"x"}`, one).Code)

	rr = santaDo(h.SantaRequestDecideHandler, "POST", "frank", `{"decision":"approve","scope":"node"}`, one)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// An approver's own request needs someone else.
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "frank", reqBody(sha, "mine"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	mine := map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}
	require.Equal(t, http.StatusForbidden,
		santaDo(h.SantaRequestDecideHandler, "POST", "frank", `{"decision":"approve","scope":"node"}`, mine).Code)
	require.Equal(t, http.StatusOK,
		santaDo(h.SantaRequestDecideHandler, "POST", "erin", `{"decision":"approve","scope":"node"}`, mine).Code)

	// Leaving the group ends the access.
	require.NoError(t, h.Santa.SetUserGroups("frank", []string{"sales"}))
	require.Equal(t, SantaAccessResponse{}, access("frank"))
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestsHandler, "GET", "frank", "", p).Code)
}
