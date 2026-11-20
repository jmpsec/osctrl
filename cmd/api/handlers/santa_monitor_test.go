package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaTemporaryMonitorGrant(t *testing.T) {
	h, p, _ := setupSantaRequests(t)
	machine := strings.ToUpper(reqMachine)
	put := func(user, body string) (int, santa.ModeOverride) {
		rr := santaDo(h.SantaModeOverrideSetHandler, "PUT", user, body, p)
		var o santa.ModeOverride
		_ = json.Unmarshal(rr.Body.Bytes(), &o)
		return rr.Code, o
	}
	grant := func(hours int) string {
		return fmt.Sprintf(`{"scope":"node","scope_value":%q,"client_mode":"MONITOR","hours":%d}`, reqMachine, hours)
	}

	tests := []struct {
		name, user, body string
		code             int
	}{
		{"requester cannot grant", "dave", grant(1), http.StatusForbidden},
		{"too long", "alice", grant(25), http.StatusBadRequest},
		{"hours on a tag", "alice", `{"scope":"tag","scope_value":"dev","client_mode":"MONITOR","hours":1}`, http.StatusBadRequest},
		{"hours with LOCKDOWN", "alice", fmt.Sprintf(`{"scope":"node","scope_value":%q,"client_mode":"LOCKDOWN","hours":1}`, reqMachine), http.StatusBadRequest},
		{"machine never synced", "alice", grant(1), http.StatusNotFound},
	}
	for _, tt := range tests {
		code, _ := put(tt.user, tt.body)
		require.Equal(t, tt.code, code, tt.name)
	}

	require.NoError(t, h.Santa.SaveMachine(&santa.Machine{EnvironmentID: 1, MachineID: machine}))
	code, o := put("alice", grant(2))
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, o.ExpiresAt)
	require.Equal(t, "MONITOR", o.ClientMode)

	// A permanent override is never replaced by a temporary one.
	code, _ = put("alice", fmt.Sprintf(`{"scope":"node","scope_value":%q,"client_mode":"LOCKDOWN"}`, reqMachine))
	require.Equal(t, http.StatusOK, code)
	code, _ = put("alice", grant(1))
	require.Equal(t, http.StatusConflict, code)
}

func TestSantaMonitorRequest(t *testing.T) {
	h, p, _ := setupSantaRequests(t)
	machine := strings.ToUpper(reqMachine)
	ask := func(user string, hours int) (int, SantaOwnRequest) {
		body := fmt.Sprintf(`{"kind":"monitor","machine_id":%q,"hours":%d,"justification":"debugging"}`, reqMachine, hours)
		rr := santaDo(h.SantaRequestCreateHandler, "POST", user, body, p)
		var own SantaOwnRequest
		_ = json.Unmarshal(rr.Body.Bytes(), &own)
		return rr.Code, own
	}
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaRequestCreateHandler, "POST", "dave", `{"kind":"other"}`, p).Code)
	code, _ := ask("dave", 4)
	require.Equal(t, http.StatusNotFound, code, "machine never synced")
	require.NoError(t, h.Santa.SaveMachine(&santa.Machine{EnvironmentID: 1, MachineID: machine}))
	code, _ = ask("dave", 0)
	require.Equal(t, http.StatusBadRequest, code)
	code, own := ask("dave", 4)
	require.Equal(t, http.StatusCreated, code)
	require.Equal(t, santa.RequestKindMonitor, own.Kind)
	require.EqualValues(t, 4, own.MonitorHours)
	code, _ = ask("erin", 8)
	require.Equal(t, http.StatusOK, code, "merged into the pending request")

	decide := func(user, body string) int {
		return santaDo(h.SantaRequestDecideHandler, "POST", user, body,
			map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}).Code
	}
	require.Equal(t, http.StatusForbidden, decide("dave", `{"decision":"approve"}`))
	require.Equal(t, http.StatusOK, decide("alice", `{"decision":"approve"}`))
	mode, source, err := h.Santa.EffectiveMode(1, machine, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"MONITOR", "node"}, []string{mode, source})
	rules, err := h.Santa.Rules(1)
	require.NoError(t, err)
	require.Empty(t, rules)

	// Approval conflicts with a permanent override and leaves the request pending.
	code, own = ask("dave", 1)
	require.Equal(t, http.StatusCreated, code)
	require.NoError(t, h.Santa.SetModeOverride(&santa.ModeOverride{EnvironmentID: 1, Scope: "node", ScopeValue: machine, ClientMode: "LOCKDOWN", CreatedBy: "alice"}))
	require.Equal(t, http.StatusConflict, decide("alice", `{"decision":"approve"}`))
}

func TestSantaMonitorEndAndExtend(t *testing.T) {
	h, p, _ := setupSantaRequests(t)
	machine := strings.ToUpper(reqMachine)
	require.NoError(t, h.Santa.SaveMachine(&santa.Machine{EnvironmentID: 1, MachineID: machine}))
	o, err := h.Santa.GrantMonitor(1, machine, 1, "alice")
	require.NoError(t, err)
	ip := map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(o.ID), 10)}
	extend := func(user string, hours int) int {
		return santaDo(h.SantaMonitorExtendHandler, "POST", user, fmt.Sprintf(`{"hours":%d}`, hours), ip).Code
	}

	require.Equal(t, http.StatusForbidden, extend("dave", 1))
	require.Equal(t, http.StatusBadRequest, extend("alice", 24), "past the maximum")
	require.Equal(t, http.StatusOK, extend("alice", 2))
	overrides, err := h.Santa.ModeOverrides(1)
	require.NoError(t, err)
	require.Len(t, overrides, 1)
	require.Greater(t, overrides[0].ExpiresAt.Unix(), o.ExpiresAt.Unix())

	// End now: the machine is back to the environment mode at its next sync.
	require.Equal(t, http.StatusNoContent, santaDo(h.SantaModeOverrideDeleteHandler, "DELETE", "alice", "", ip).Code)
	_, source, err := h.Santa.EffectiveMode(1, machine, nil)
	require.NoError(t, err)
	require.Equal(t, "env", source)
	require.Equal(t, http.StatusNotFound, extend("alice", 1))
}
