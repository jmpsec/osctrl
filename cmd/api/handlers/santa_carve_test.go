package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestSantaEventCarve(t *testing.T) {
	f := setupTiers(t)
	mgr, err := santa.NewManager(f.h.DB)
	require.NoError(t, err)
	f.h.Santa = mgr
	f.user(t, "viewer")
	require.NoError(t, f.h.Users.CreatePermission(users.UserPermission{
		Username: "viewer", AccessType: int(users.UserLevel), AccessValue: true, Environment: f.env.UUID, EnvironmentID: f.env.ID,
	}))
	evs := []santa.Event{
		{EnvironmentID: f.env.ID, MachineID: f.n1.UUID, FilePath: "/Applications/Tool.app/Contents/MacOS", FileName: "tool"},
		{EnvironmentID: f.env.ID, MachineID: "NOT-ENROLLED", FilePath: "/usr/local/bin", FileName: "x"},
		{EnvironmentID: f.env.ID, MachineID: f.b1.UUID, FilePath: "/usr/local/bin", FileName: "x"}, // node of the other env
		{EnvironmentID: f.env.ID, MachineID: f.n1.UUID, FilePath: "~/bin", FileName: "x"},          // refused by the carves handler
		{EnvironmentID: f.other.ID, MachineID: f.b1.UUID, FilePath: "/usr/local/bin", FileName: "x"},
		{EnvironmentID: f.env.ID, MachineID: f.n1.UUID},
	}
	require.NoError(t, mgr.AddEvents(evs))
	post := func(user string, ev santa.Event) (int, string) {
		rr := santaDo(f.h.SantaEventCarveHandler, http.MethodPost, user, "", map[string]string{"env": f.env.Name, "id": strconv.Itoa(int(ev.ID))})
		return rr.Code, rr.Body.String()
	}
	carves := func() int64 {
		var n int64
		require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("type = ?", queries.CarveQueryType).Count(&n).Error)
		return n
	}

	code, body := post("viewer", evs[0])
	require.Equal(t, http.StatusForbidden, code, body)

	code, body = post("alice", evs[0])
	require.Equal(t, http.StatusCreated, code, body)
	var created types.ApiQueriesResponse
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	q, err := f.h.Queries.Get(created.Name, f.env.ID)
	require.NoError(t, err)
	require.Equal(t, "/Applications/Tool.app/Contents/MacOS/tool", q.Path)
	require.EqualValues(t, 1, q.Expected)
	got, err := mgr.Event(f.env.ID, evs[0].ID)
	require.NoError(t, err)
	require.Equal(t, created.Name, got.CarveName)

	tests := []struct {
		name string
		ev   santa.Event
		code int
	}{
		{"machine not enrolled", evs[1], http.StatusConflict},
		{"node of another environment", evs[2], http.StatusConflict},
		{"path refused by the carves handler", evs[3], http.StatusBadRequest},
		{"event of another environment", evs[4], http.StatusNotFound},
		{"no path", evs[5], http.StatusConflict},
	}
	for _, tt := range tests {
		code, body := post("alice", tt.ev)
		require.Equal(t, tt.code, code, tt.name+": "+body)
		got, err := mgr.Event(tt.ev.EnvironmentID, tt.ev.ID)
		require.NoError(t, err)
		require.Empty(t, got.CarveName, tt.name)
	}
	require.EqualValues(t, 1, carves())
}

func TestSantaEventFullPath(t *testing.T) {
	for _, tt := range []struct{ dir, name, want string }{
		{"/Applications/Tool.app/Contents/MacOS", "tool", "/Applications/Tool.app/Contents/MacOS/tool"},
		{"/usr/local/bin/tool", "tool", "/usr/local/bin/tool"},
		{"/usr/local/bin", "", "/usr/local/bin"},
		{"", "tool", ""},
	} {
		require.Equal(t, tt.want, santa.Event{FilePath: tt.dir, FileName: tt.name}.FullPath(), tt.dir)
	}
}
