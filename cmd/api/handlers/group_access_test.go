package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/scim"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestGroupMappings(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	tok := setupSCIM(t, h)
	mux := scimMux(h)
	put := func(user, body string) (int, GroupMappingsResponse) {
		t.Helper()
		rr := santaDo(h.GroupMappingsPutHandler, "PUT", user, body, nil)
		var out GroupMappingsResponse
		if rr.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		}
		return rr.Code, out
	}
	audited := func(substr string) bool {
		t.Helper()
		var lines []string
		require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
		return strings.Contains(strings.Join(lines, "\n"), substr)
	}
	security := `[{"group":"Security","roles":["read_only_admin"],"environments":[{"environment":"` + envA.UUID + `","user":true,"query_tier":"standard"}]}]`

	// Changing the mapping needs superuser; superuser is never a mapped role.
	code, _ := put("alice", security)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, http.StatusForbidden, santaDo(h.GroupMappingsHandler, "GET", "alice", "", nil).Code)
	code, _ = put("root", `[{"group":"Security","roles":["superuser"]}]`)
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = put("root", `[{"group":"Security","environments":[{"environment":"nope","user":true}]}]`)
	require.Equal(t, http.StatusBadRequest, code)
	code, out := put("root", security)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, out.Mappings, 1)
	require.Equal(t, "root", out.Mappings[0].UpdatedBy)
	require.True(t, audited("users: set group mappings groups=Security"))

	// Joining the group at the IdP grants the access, with no osctrl login.
	var u scim.UserResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Users", tok, `{"userName":"jdoe"}`, &u))
	var g scim.GroupResource
	require.Equal(t, http.StatusCreated, scimDo(t, mux, "POST", "/v2/Groups", tok, `{"displayName":"Security","members":[{"value":"`+u.ID+`"}]}`, &g))
	require.True(t, account(t, h, "jdoe").ReadOnlyAdmin)
	require.True(t, h.Users.CheckPermissions("jdoe", users.QueryLevel, envA.UUID))
	require.True(t, audited("idp groups: grant jdoe role:read_only_admin=true"))

	// Access granted by hand stays when the user leaves the group.
	require.NoError(t, h.Users.SetRoles("jdoe", users.RoleSet{AlertAdmin: ptrBool(true)}))
	require.NoError(t, h.Users.SetEnvAdmin("jdoe", envB.UUID, true))
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PUT", "/v2/Groups/"+g.ID, tok, `{"displayName":"Security","members":[]}`, nil))
	jdoe := account(t, h, "jdoe")
	require.False(t, jdoe.ReadOnlyAdmin)
	require.False(t, h.Users.CheckPermissions("jdoe", users.QueryLevel, envA.UUID))
	require.True(t, jdoe.AlertAdmin)
	require.True(t, h.Users.CheckPermissions("jdoe", users.AdminLevel, envB.UUID))
	require.True(t, audited("idp groups: revoke jdoe role:read_only_admin (was true)"))

	// A mapping change applies to the users osctrl has seen the groups of.
	require.Equal(t, http.StatusOK, scimDo(t, mux, "PUT", "/v2/Groups/"+g.ID, tok, `{"displayName":"Security","members":[{"value":"`+u.ID+`"}]}`, nil))
	code, out = put("root", `[{"group":"Security","environments":[{"environment":"`+envA.UUID+`","carve_tier":"full"}]}]`)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 4, out.Changes, "read-only, user and query revoked; carve granted")
	jdoe = account(t, h, "jdoe")
	require.False(t, jdoe.ReadOnlyAdmin)
	require.True(t, h.Users.CheckPermissions("jdoe", users.CarveLevel, envA.UUID))

	// An SSO login with a groups claim applies the mappings to other users.
	h.recordSSOGroups("carol", []string{"Security"}, "127.0.0.1")
	require.True(t, h.Users.CheckPermissions("carol", users.CarveLevel, envA.UUID))
	h.recordSSOGroups("carol", nil, "127.0.0.1")
	require.True(t, h.Users.CheckPermissions("carol", users.CarveLevel, envA.UUID), "no groups claim changes nothing")
	h.recordSSOGroups("carol", []string{}, "127.0.0.1")
	require.False(t, h.Users.CheckPermissions("carol", users.CarveLevel, envA.UUID))
	// SCIM-provisioned users keep the groups SCIM gives them.
	h.recordSSOGroups("jdoe", []string{}, "127.0.0.1")
	require.True(t, h.Users.CheckPermissions("jdoe", users.CarveLevel, envA.UUID))

	rr := santaDo(h.GroupMappingsHandler, "GET", "root", "", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"carve_tier":"full"`)
}

func ptrBool(b bool) *bool { return &b }
