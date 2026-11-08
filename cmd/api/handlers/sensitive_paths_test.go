package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func (f tierFixture) spCall(t *testing.T, fn http.HandlerFunc, method, user, env, id, path string) *httptest.ResponseRecorder {
	t.Helper()
	require.NoError(t, f.h.DB.AutoMigrate(&environments.SensitivePath{}))
	r := consoleRequest(method, "/sp", mustJSON(t, types.ApiSensitivePathRequest{Path: path}), user)
	r.RemoteAddr = "127.0.0.1:1234"
	r.SetPathValue("env", env)
	r.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	fn(rr, r)
	return rr
}

func TestSensitivePathsAPIPermissions(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	f.user(t, "ro")
	require.NoError(t, f.h.Users.SetRoles("ro", users.RoleSet{ReadOnlyAdmin: boolPtr(true)}))
	row, err := func() (environments.SensitivePath, error) {
		require.NoError(t, f.h.DB.AutoMigrate(&environments.SensitivePath{}))
		return f.h.Envs.AddSensitivePath(f.env.ID, "/etc/shadow", "alice")
	}()
	require.NoError(t, err)
	id := strconv.Itoa(int(row.ID))
	for _, tc := range []struct {
		user           string
		list, add, del int
	}{
		{"std", 403, 403, 403},
		{"ro", 200, 403, 403},
	} {
		require.Equal(t, tc.list, f.spCall(t, f.h.SensitivePathsListHandler, "GET", tc.user, f.env.Name, "", "").Code, tc.user)
		require.Equal(t, tc.add, f.spCall(t, f.h.SensitivePathsAddHandler, "POST", tc.user, f.env.Name, "", "/tmp").Code, tc.user)
		require.Equal(t, tc.del, f.spCall(t, f.h.SensitivePathsDeleteHandler, "DELETE", tc.user, f.env.Name, id, "").Code, tc.user)
	}
	require.Equal(t, 200, f.spCall(t, f.h.SensitivePathsListHandler, "GET", "alice", f.env.Name, "", "").Code)
	require.Equal(t, 201, f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/tmp").Code)
	require.Equal(t, 200, f.spCall(t, f.h.SensitivePathsDeleteHandler, "DELETE", "alice", f.env.Name, id, "").Code)
}

func TestSensitivePathsAPIValidation(t *testing.T) {
	f := setupTiers(t)
	rr := f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "etc/shadow")
	require.Equal(t, 400, rr.Code)
	require.Contains(t, rr.Body.String(), "path must be absolute")
	rr = f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/ETC//shadow")
	require.Equal(t, 201, rr.Code, rr.Body.String())
	rows, err := f.h.Envs.SensitivePaths(f.env.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "/etc/shadow", rows[0].Path)
	require.Equal(t, 404, f.spCall(t, f.h.SensitivePathsListHandler, "GET", "alice", "nope", "", "").Code)
}

func TestSensitivePathsAPIDeleteOtherEnv(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "root2")
	require.NoError(t, f.h.Users.ChangeAdmin("root2", true))
	require.NoError(t, f.h.DB.AutoMigrate(&environments.SensitivePath{}))
	row, err := f.h.Envs.AddSensitivePath(f.other.ID, "/etc/shadow", "x")
	require.NoError(t, err)
	rr := f.spCall(t, f.h.SensitivePathsDeleteHandler, "DELETE", "root2", f.env.Name, strconv.Itoa(int(row.ID)), "")
	require.Equal(t, 404, rr.Code, rr.Body.String())
	rows, _ := f.h.Envs.SensitivePaths(f.other.ID)
	require.Len(t, rows, 1)
}

func TestSensitivePathAddCancelsPending(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	f.tier(t, "alice", f.env.UUID, users.CarveLevel, users.TierFull)
	mk := func(creator, name, path string, nodeID uint) uint {
		dq := queries.DistributedQuery{Name: name, Creator: creator, Type: queries.CarveQueryType, Path: path, EnvironmentID: f.env.ID, Expected: 1}
		require.NoError(t, f.h.DB.Create(&dq).Error)
		nq := queries.NodeQuery{NodeID: nodeID, QueryID: dq.ID, Status: queries.DistributedQueryStatusPending}
		require.NoError(t, f.h.DB.Create(&nq).Error)
		return nq.ID
	}
	std := mk("std", "c-std", "/etc/shadow/key", f.n1.ID)
	stdOther := mk("std", "c-std2", "/etc/hosts", f.n1.ID)
	admin := mk("alice", "c-alice", "/etc/shadow/key", f.n1.ID)
	ghost := mk("gone", "c-ghost", "/etc/shadow", f.n2.ID)
	otherEnv := mk("std", "c-b", "/etc/shadow", f.b1.ID)
	require.Equal(t, 201, f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/etc/shadow").Code)
	require.False(t, f.pendingExists(t, std))
	require.False(t, f.pendingExists(t, ghost))
	require.True(t, f.pendingExists(t, stdOther))
	require.True(t, f.pendingExists(t, admin))
	require.True(t, f.pendingExists(t, otherEnv))
}

func TestSensitivePathAudited(t *testing.T) {
	f := setupTiers(t)
	f.h.AuditLog.Enabled = true
	rr := f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/etc/shadow")
	require.Equal(t, 201, rr.Code, rr.Body.String())
	rows, _ := f.h.Envs.SensitivePaths(f.env.ID)
	require.Equal(t, 200, f.spCall(t, f.h.SensitivePathsDeleteHandler, "DELETE", "alice", f.env.Name, strconv.Itoa(int(rows[0].ID)), "").Code)
	var lines []string
	require.NoError(t, f.h.DB.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	require.Contains(t, lines, "user alice performed environment action: sensitive path add /etc/shadow")
	require.Contains(t, lines, "user alice performed environment action: sensitive path remove /etc/shadow")
}

func TestSensitivePathsAPITooLong(t *testing.T) {
	f := setupTiers(t)
	rr := f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/"+strings.Repeat("a", 600))
	require.Equal(t, 400, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "path too long")
}

func TestSensitivePathAddKeepsConsoleCarveOfFullUser(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	mk := func(creator, name string) uint {
		dq := queries.DistributedQuery{Name: name, Creator: creator, Type: queries.CarveQueryType, Path: "/etc/shadow", EnvironmentID: f.env.ID, Expected: 1}
		require.NoError(t, f.h.DB.Create(&dq).Error)
		nq := queries.NodeQuery{NodeID: f.n1.ID, QueryID: dq.ID, Status: queries.DistributedQueryStatusPending}
		require.NoError(t, f.h.DB.Create(&nq).Error)
		return nq.ID
	}
	admin := mk("console:alice", "c-alice")
	std := mk("console:std", "c-std")
	require.Equal(t, 201, f.spCall(t, f.h.SensitivePathsAddHandler, "POST", "alice", f.env.Name, "", "/etc/shadow").Code)
	require.True(t, f.pendingExists(t, admin))
	require.False(t, f.pendingExists(t, std))
}
