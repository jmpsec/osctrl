package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestSCIM(t *testing.T) {
	h, db, envA, _ := setupSantaHandlers(t)
	var err error
	h.SCIM, err = scim.NewManager(db)
	require.NoError(t, err)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	mux := scimMux(h)

	// Token management is for superusers; SCIM is off until a token exists.
	require.Equal(t, http.StatusForbidden, santaDo(h.SCIMStatusHandler, "GET", "alice", "", nil).Code)
	require.Equal(t, http.StatusForbidden, santaDo(h.SCIMTokenHandler, "POST", "alice", "", nil).Code)
	var st SCIMStatusResponse
	rr := santaDo(h.SCIMStatusHandler, "GET", "root", "", nil)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &st))
	require.Equal(t, SCIMStatusResponse{Available: true}, st)
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", "", "", nil))
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", "guess", "", nil))

	rr = santaDo(h.SCIMTokenHandler, "POST", "root", "", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	var tok SCIMTokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", "/v2/ServiceProviderConfig", tok.Token, "", nil))

	// Map the IdP group to a tag, as #1180 does for SSO groups.
	require.NoError(t, h.Tags.NewTag("finance", "", "", "", "alice", envA.ID, false, tags.TagTypeTag, ""))
	require.Equal(t, http.StatusOK, santaDo(h.SantaConfigPutHandler, "PUT", "alice",
		`{"client_mode":"MONITOR","group_tags":[{"group":"Finance","tag":"finance"}]}`, map[string]string{"env": envA.Name}).Code)
	groupTags := func() []string {
		got, err := h.Santa.GroupTags(envA.ID, "jdoe")
		require.NoError(t, err)
		return got
	}

	// Okta: look the user up, create it, then push the group.
	var list SCIMListResponse
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", `/v2/Users?filter=userName+eq+%22jdoe%22`, tok.Token, "", &list))
	require.Zero(t, list.TotalResults)
	var u scim.UserResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Users", tok.Token,
		`{"schemas":["`+scim.SchemaUser+`"],"userName":"jdoe","name":{"givenName":"J"},"emails":[{"value":"j@example.com"}],"active":true}`, &u))
	require.Equal(t, http.StatusConflict, scimDo(t, mux, "POST", "/v2/Users", tok.Token, `{"userName":"JDOE"}`, nil))
	var g scim.GroupResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Groups", tok.Token,
		`{"displayName":"Finance","members":[{"value":"`+u.ID+`"}]}`, &g))
	require.Equal(t, []string{"finance"}, groupTags())

	// A later SSO login does not overwrite the groups SCIM provisions.
	h.santaRecordGroups("jdoe", []string{})
	require.Equal(t, []string{"finance"}, groupTags())

	require.Equal(t, http.StatusBadRequest, scimDo(t, mux, "GET", `/v2/Groups?filter=displayName+co+%22F%22`, tok.Token, "", nil))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "GET", `/v2/Groups?filter=displayName+eq+%22Finance%22&excludedAttributes=members`, tok.Token, "", &list))
	require.EqualValues(t, 1, list.TotalResults)
	require.Equal(t, http.StatusBadRequest, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok.Token,
		`{"Operations":[{"op":"add","path":"members","value":[{"value":"unknown"}]}]}`, nil))
	require.Equal(t, http.StatusNotFound, scimDo(t, mux, "GET", "/v2/Users/unknown", tok.Token, "", nil))

	// Removing the user from the group at the IdP removes the tag, no login.
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok.Token,
		`{"Operations":[{"op":"remove","path":"members[value eq \"`+u.ID+`\"]"}]}`, nil))
	require.Empty(t, groupTags())

	// The user page shows the stored groups.
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PATCH", "/v2/Groups/"+g.ID, tok.Token,
		`{"Operations":[{"op":"Add","path":"members","value":[{"value":"`+u.ID+`"}]}]}`, nil))
	require.Equal(t, http.StatusForbidden, santaDo(h.UserGroupsHandler, "GET", "carol", "", map[string]string{"username": "jdoe"}).Code)
	var ug UserGroupsResponse
	rr = santaDo(h.UserGroupsHandler, "GET", "root", "", map[string]string{"username": "JDoe"})
	require.Equal(t, http.StatusOK, rr.Code)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &ug))
	require.Equal(t, []string{"Finance"}, ug.Groups)
	require.True(t, ug.SCIM)
	require.NotNil(t, ug.UpdatedAt)

	// Deprovisioning removes the groups.
	require.Equal(t, http.StatusNoContent, scimDo(t, mux, "DELETE", "/v2/Users/"+u.ID, tok.Token, "", nil))
	require.Empty(t, groupTags())

	// Removing the token turns SCIM off.
	require.Equal(t, http.StatusNoContent, santaDo(h.SCIMTokenHandler, "DELETE", "root", "", nil).Code)
	require.Equal(t, http.StatusUnauthorized, scimDo(t, mux, "GET", "/v2/Users", tok.Token, "", nil))

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Where("line LIKE ?", "%scim:%").Order("id").Pluck("line", &lines).Error)
	require.Equal(t, []string{
		"user root performed user action: scim: rotate token",
		"user scim performed user action: scim: create user jdoe",
		"user scim performed user action: scim: create group Finance members=1",
		"user scim performed user action: scim: update group Finance members=0",
		"user scim performed user action: scim: update group Finance members=1",
		"user scim performed user action: scim: delete user jdoe",
		"user root performed user action: scim: remove token",
	}, lines)
}
