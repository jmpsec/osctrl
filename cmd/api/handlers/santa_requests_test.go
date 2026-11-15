package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

const reqMachine = "22222222-2222-4222-8222-222222222222"

// dave and erin have no permission anywhere: they are requesters.
func setupSantaRequests(t *testing.T) (*HandlersApi, map[string]string, string) {
	t.Helper()
	h, _, envA, envB := setupSantaHandlers(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "dave"}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "erin"}))
	require.NoError(t, h.Santa.SaveConfig(santa.EnvConfig{EnvironmentID: envA.ID, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com"}))
	sha := strings.Repeat("ab", 32)
	require.NoError(t, h.Santa.AddEvents([]santa.Event{
		{EnvironmentID: envA.ID, MachineID: strings.ToUpper(reqMachine), Decision: "BLOCK_UNKNOWN", FileSHA256: sha, FileName: "tool", FilePath: "/Users/dave/secret-project/tool"},
		{EnvironmentID: envB.ID, MachineID: strings.ToUpper(reqMachine), Decision: "BLOCK_UNKNOWN", FileSHA256: sha},
	}))
	return h, map[string]string{"env": envA.UUID}, sha
}

func reqBody(sha, why string) string {
	b, _ := json.Marshal(SantaRequestCreate{SHA256: sha, MachineID: reqMachine, Justification: why})
	return string(b)
}

func TestSantaRequestCreateAndMerge(t *testing.T) {
	h, p, sha := setupSantaRequests(t)

	rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "I need this tool"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	require.Equal(t, santa.RequestPending, own.Status)
	require.Equal(t, "I need this tool", own.Justification)
	// Nothing from the event reaches the requester.
	require.NotContains(t, rr.Body.String(), "secret-project")
	require.NotContains(t, rr.Body.String(), "requester")

	// The same user again, then another user: one request, and erin does not
	// get dave's justification.
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "again"), p)
	require.Equal(t, http.StatusOK, rr.Code)
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "erin", reqBody(sha, "me too"), p)
	require.Equal(t, http.StatusOK, rr.Code)
	require.NotContains(t, rr.Body.String(), "I need this tool")
	require.NotContains(t, rr.Body.String(), "dave")

	// Own list: dave sees his request, erin sees nothing.
	rr = santaDo(h.SantaMyRequestsHandler, "GET", "dave", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	var mine []SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &mine))
	require.Len(t, mine, 1)
	rr = santaDo(h.SantaMyRequestsHandler, "GET", "erin", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	require.JSONEq(t, `[]`, rr.Body.String())

	// The full list is for environment admins only.
	for _, who := range []string{"dave", "carol"} {
		require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestsHandler, "GET", who, "", p).Code, who)
	}
	rr = santaDo(h.SantaRequestsHandler, "GET", "alice", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	var all []santa.Request
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &all))
	require.Len(t, all, 1)
	require.Equal(t, "dave", all[0].Requester)
	require.Equal(t, "tool", all[0].FileName)
	rr = santaDoURL(h.SantaRequestsHandler, "GET", "/x?status=denied", "alice", "", p)
	require.JSONEq(t, `[]`, rr.Body.String())
}

func TestSantaRequestRefusals(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	const envB = "env-b"
	tests := []struct {
		name string
		path map[string]string
		body string
		code int
	}{
		{"bad json", p, "{", http.StatusBadRequest},
		{"bad hash", p, reqBody("zz", "why"), http.StatusBadRequest},
		{"no justification", p, reqBody(sha, " "), http.StatusBadRequest},
		{"file never blocked", p, reqBody(strings.Repeat("cd", 32), "why"), http.StatusNotFound},
		// env-b has the block but approval requests are off there.
		{"approval off", map[string]string{"env": envB}, reqBody(sha, "why"), http.StatusNotFound},
		{"unknown environment", map[string]string{"env": "nope"}, reqBody(sha, "why"), http.StatusNotFound},
	}
	var notFound []string
	for _, tt := range tests {
		rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", tt.body, tt.path)
		require.Equal(t, tt.code, rr.Code, tt.name)
		if tt.code == http.StatusNotFound {
			notFound = append(notFound, rr.Body.String())
		}
	}
	// One answer for all three, so the route tells a requester nothing.
	require.Len(t, notFound, 3)
	require.Equal(t, notFound[0], notFound[1])
	require.Equal(t, notFound[0], notFound[2])
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaMyRequestsHandler, "GET", "dave", "", map[string]string{"env": envB}).Code)

	all, err := h.Santa.Requests(1, "", "")
	require.NoError(t, err)
	require.Empty(t, all, "a refused request was stored")
}

func TestSantaConfigApprovalURL(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	p := map[string]string{"env": envA.Name}
	rr := santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com/"}`, p)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var cfg SantaConfigResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &cfg))
	require.Equal(t, "https://osctrl.example.com", cfg.ApprovalURL)
	rr = santaDo(h.SantaConfigPutHandler, "PUT", "alice", `{"client_mode":"LOCKDOWN","approval_url":"http://osctrl.example.com"}`, p)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSantaRequestDecide(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "I need this tool"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	path := func(env string, id uint) map[string]string {
		return map[string]string{"env": env, "id": strconv.FormatUint(uint64(id), 10)}
	}
	one := path(p["env"], own.ID)
	const approve = `{"decision":"approve","scope":"node"}`

	// Requesters, non-admin members and admins of another environment cannot decide.
	for _, who := range []string{"dave", "erin", "carol"} {
		require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestDecideHandler, "POST", who, approve, one).Code, who)
	}
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestDecideHandler, "POST", "alice", approve, path("env-b", own.ID)).Code)

	tests := []struct {
		name string
		path map[string]string
		body string
		code int
	}{
		{"bad json", one, "{", http.StatusBadRequest},
		{"bad id", map[string]string{"env": p["env"], "id": "x"}, approve, http.StatusBadRequest},
		{"unknown decision", one, `{"decision":"maybe"}`, http.StatusBadRequest},
		{"deny without reason", one, `{"decision":"deny"}`, http.StatusBadRequest},
		{"bad scope", one, `{"decision":"approve","scope":"all"}`, http.StatusBadRequest},
		{"tag without name", one, `{"decision":"approve","scope":"tag"}`, http.StatusBadRequest},
		{"unknown request", path(p["env"], own.ID+100), approve, http.StatusNotFound},
	}
	for _, tt := range tests {
		require.Equal(t, tt.code, santaDo(h.SantaRequestDecideHandler, "POST", "alice", tt.body, tt.path).Code, tt.name)
	}
	rules, err := h.Santa.Rules(1)
	require.NoError(t, err)
	require.Empty(t, rules, "a refused decision created a rule")

	rr = santaDo(h.SantaRequestDecideHandler, "POST", "alice", approve, one)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var req santa.Request
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &req))
	require.Equal(t, santa.RequestApproved, req.Status)
	require.Equal(t, "alice", req.DecidedBy)
	rules, err = h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, req.RuleID, rules[0].ID)
	require.Equal(t, strings.ToUpper(reqMachine), rules[0].ScopeValue)
	require.Equal(t, "alice", rules[0].CreatedBy)

	// Deciding again changes nothing.
	for _, body := range []string{approve, `{"decision":"deny","reason":"changed my mind"}`} {
		require.Equal(t, http.StatusConflict, santaDo(h.SantaRequestDecideHandler, "POST", "alice", body, one).Code)
	}
	rules, err = h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// A denial reaches the requester with its reason.
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "once more"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	rr = santaDo(h.SantaRequestDecideHandler, "POST", "alice", `{"decision":"deny","reason":"not company software"}`, path(p["env"], own.ID))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = santaDo(h.SantaMyRequestsHandler, "GET", "dave", "", p)
	var mine []SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &mine))
	require.Len(t, mine, 2)
	require.Equal(t, santa.RequestDenied, mine[0].Status)
	require.Equal(t, "not company software", mine[0].Reason)
	require.NotContains(t, rr.Body.String(), "alice")
}
