package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/scim"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func scimMux(h *HandlersApi) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /v2/ServiceProviderConfig", h.SCIMAuth(http.HandlerFunc(h.SCIMServiceProviderConfigHandler)))
	for _, m := range []string{"GET", "POST"} {
		mux.Handle(m+" /v2/Users", h.SCIMAuth(http.HandlerFunc(h.SCIMUsersHandler)))
		mux.Handle(m+" /v2/Groups", h.SCIMAuth(http.HandlerFunc(h.SCIMGroupsHandler)))
	}
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.Handle(m+" /v2/Users/{id}", h.SCIMAuth(http.HandlerFunc(h.SCIMUserHandler)))
		mux.Handle(m+" /v2/Groups/{id}", h.SCIMAuth(http.HandlerFunc(h.SCIMGroupHandler)))
	}
	return mux
}

func scimDo(t *testing.T, mux http.Handler, method, url, token, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if out != nil && rr.Code < 300 {
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), out), rr.Body.String())
	}
	if rr.Code >= 400 {
		require.Equal(t, scimJSON, rr.Header().Get("Content-Type"))
	}
	return rr.Code
}

// setupSCIM adds the SCIM store and a superuser, and returns a fresh token.
func setupSCIM(t *testing.T, h *HandlersApi) string {
	t.Helper()
	var err error
	h.SCIM, err = scim.NewManager(h.DB)
	require.NoError(t, err)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	rr := santaDo(h.SCIMTokenHandler, "POST", "root", "", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	var tok SCIMTokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	return tok.Token
}

func account(t *testing.T, h *HandlersApi, name string) users.AdminUser {
	t.Helper()
	a, err := h.Users.Get(name)
	require.NoError(t, err)
	return a
}

func TestSCIMTokenManagement(t *testing.T) {
	h, db, _, _ := setupSantaHandlers(t)
	var err error
	h.SCIM, err = scim.NewManager(db)
	require.NoError(t, err)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	mux := scimMux(h)

	require.Equal(t, http.StatusForbidden, santaDo(h.SCIMStatusHandler, "GET", "alice", "", nil).Code)
	require.Equal(t, http.StatusForbidden, santaDo(h.SCIMTokenHandler, "POST", "alice", "", nil).Code)
	var st SCIMStatusResponse
	require.NoError(t, json.Unmarshal(santaDo(h.SCIMStatusHandler, "GET", "root", "", nil).Body.Bytes(), &st))
	require.False(t, st.Enabled)
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", "", "", nil))
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", "guess", "", nil))

	rr := santaDo(h.SCIMTokenHandler, "POST", "root", "", nil)
	var tok SCIMTokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", "/v2/ServiceProviderConfig", tok.Token, "", nil))
	require.NoError(t, json.Unmarshal(santaDo(h.SCIMStatusHandler, "GET", "root", "", nil).Body.Bytes(), &st))
	require.True(t, st.Enabled)

	require.Equal(t, http.StatusNoContent, santaDo(h.SCIMTokenHandler, "DELETE", "root", "", nil).Code)
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", tok.Token, "", nil))
}

func TestSCIMAccounts(t *testing.T) {
	h, db, _, _ := setupSantaHandlers(t)
	h.Santa = nil // accounts do not depend on Santa
	tok := setupSCIM(t, h)
	mux := scimMux(h)

	// A local password account is never taken over.
	require.Equal(t, http.StatusConflict, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"alice"}`, nil))
	require.Equal(t, http.StatusBadRequest, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"no spaces"}`, nil))

	// Entra ID creates the user: an SSO account with no access appears.
	var u scim.UserResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Users", tok,
		`{"userName":"JDoe@Example.com","displayName":"J Doe","emails":[{"value":"jdoe@example.com","type":"work","primary":true}],"active":true}`, &u))
	a := account(t, h, "jdoe@example.com")
	require.Equal(t, "scim", a.AuthSource)
	require.False(t, a.Admin)
	require.False(t, a.Disabled)
	require.Equal(t, "jdoe@example.com", a.Email)
	require.Equal(t, "J Doe", a.Fullname)
	perms, err := h.Users.GetAllPermissions("jdoe@example.com")
	require.NoError(t, err)
	require.Empty(t, perms)

	// Give the account access and a session, then deactivate it at the IdP.
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{Username: a.Username, Environment: "env-a", AccessType: int(users.UserLevel), AccessValue: true}))
	require.NoError(t, h.Users.UpdateToken(a.Username, "session", time.Now().Add(time.Hour)))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Users/"+u.ID, tok,
		`{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, nil))
	a = account(t, h, "jdoe@example.com")
	require.True(t, a.Disabled)
	require.Empty(t, a.APIToken, "disabling ends the session")
	// Reactivating restores the same account with its access.
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Users/"+u.ID, tok,
		`{"Operations":[{"op":"replace","value":{"active":true,"displayName":"Jane Doe"}}]}`, nil))
	a = account(t, h, "jdoe@example.com")
	require.False(t, a.Disabled)
	require.Equal(t, "Jane Doe", a.Fullname)
	require.True(t, h.Users.CheckPermissions(a.Username, users.UserLevel, "env-a"))
	// A userName change keeps the account.
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Users/"+u.ID, tok,
		`{"Operations":[{"op":"replace","path":"userName","value":"jane@example.com"}]}`, nil))
	require.False(t, h.Users.Exists("jane@example.com"))

	// Groups are kept without Santa and shown on the user page.
	var g scim.GroupResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Groups", tok, `{"displayName":"Finance","members":[{"value":"`+u.ID+`"}]}`, &g))
	var ug UserGroupsResponse
	rr := santaDo(h.UserGroupsHandler, "GET", "root", "", map[string]string{"username": a.Username})
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &ug))
	require.Equal(t, UserGroupsResponse{Groups: []string{"Finance"}, SCIM: true}, ug)
	require.Equal(t, http.StatusForbidden, santaDo(h.UserGroupsHandler, "GET", "carol", "", map[string]string{"username": a.Username}).Code)

	// The last active superuser is never disabled or deleted.
	var boss scim.UserResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"boss"}`, &boss))
	require.NoError(t, h.Users.ChangeAdmin("boss", true))
	require.NoError(t, h.Users.SetDisabled("root", true))
	require.Equal(t, http.StatusConflict, scimDo(t, mux, "PATCH", "/v2/Users/"+boss.ID, tok, `{"Operations":[{"op":"replace","path":"active","value":false}]}`, nil))
	require.Equal(t, http.StatusConflict, scimDo(t, mux, "DELETE", "/v2/Users/"+boss.ID, tok, "", nil))
	require.False(t, account(t, h, "boss").Disabled)
	require.NoError(t, h.Users.SetDisabled("root", false))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Users/"+boss.ID, tok, `{"Operations":[{"op":"replace","path":"active","value":false}]}`, nil))
	require.True(t, account(t, h, "boss").Disabled)

	// Deprovisioning deletes the account and its permissions.
	require.Equal(t, http.StatusNoContent, scimDo(t, mux, "DELETE", "/v2/Users/"+u.ID, tok, "", nil))
	require.False(t, h.Users.Exists("jdoe@example.com"))
	var left int64
	require.NoError(t, db.Model(&users.UserPermission{}).Where("username = ?", "jdoe@example.com").Count(&left).Error)
	require.Zero(t, left)
	require.Equal(t, http.StatusNotFound, scimDo(t, mux, "GET", "/v2/Users/"+u.ID, tok, "", nil))

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Where("line LIKE ?", "%scim:%").Order("id").Pluck("line", &lines).Error)
	require.Contains(t, lines, "user scim performed user action: scim: create user jdoe@example.com account=jdoe@example.com active=true")
	require.Contains(t, lines, "user scim performed user action: scim: update user jdoe@example.com account=jdoe@example.com active=false")
	require.Contains(t, lines, "user scim performed user action: scim: delete user jane@example.com account=jdoe@example.com")
}

// Removing a user from a group at the IdP removes the mapped Santa tag at the
// next sync, with no login (#1208).
func TestSCIMSantaGroupTags(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	tok := setupSCIM(t, h)
	mux := scimMux(h)
	require.NoError(t, h.Tags.NewTag("finance", "", "", "", "alice", envA.ID, false, tags.TagTypeTag, ""))
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice",
		`{"client_mode":"MONITOR","group_tags":[{"group":"Finance","tag":"finance"}]}`, map[string]string{"env": envA.Name}).Code)
	groupTags := func() []string {
		got, err := h.Santa.GroupTags(envA.ID, "jdoe")
		require.NoError(t, err)
		return got
	}

	var list SCIMListResponse
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", `/v2/Users?filter=userName+eq+%22jdoe%22`, tok, "", &list))
	require.Zero(t, list.TotalResults)
	var u scim.UserResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"jdoe"}`, &u))
	require.Equal(t, http.StatusConflict, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"JDOE"}`, nil))
	var g scim.GroupResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Groups", tok, `{"displayName":"Finance","members":[{"value":"`+u.ID+`"}]}`, &g))
	require.Equal(t, []string{"finance"}, groupTags())

	// A later SSO login does not overwrite the groups SCIM provisions.
	h.santaRecordGroups("jdoe", []string{})
	require.Equal(t, []string{"finance"}, groupTags())

	require.Equal(t, http.StatusBadRequest, scimDo(t, mux, "GET", `/v2/Groups?filter=displayName+co+%22F%22`, tok, "", nil))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", `/v2/Groups?filter=displayName+eq+%22Finance%22&excludedAttributes=members`, tok, "", &list))
	require.EqualValues(t, 1, list.TotalResults)
	require.Equal(t, http.StatusBadRequest, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok,
		`{"Operations":[{"op":"add","path":"members","value":[{"value":"unknown"}]}]}`, nil))

	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok,
		`{"Operations":[{"op":"remove","path":"members[value eq \"`+u.ID+`\"]"}]}`, nil))
	require.Empty(t, groupTags())
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok,
		`{"Operations":[{"op":"Add","path":"members","value":[{"value":"`+u.ID+`"}]}]}`, nil))
	require.Equal(t, []string{"finance"}, groupTags())

	// Deprovisioning removes the groups.
	require.Equal(t, http.StatusNoContent, scimDo(t, mux, "DELETE", "/v2/Users/"+u.ID, tok, "", nil))
	require.Empty(t, groupTags())
}
