package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaRequesterEmail(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	notifier := make(fakeNotifier, 4)
	h.SantaNotify = notifier
	h.Alerts = alerts.NewManager(h.DB)
	hook := webhookChannel(t, h.Alerts, "hook", alerts.NoEnvironmentID)
	mail, err := h.Alerts.CreateChannel(alerts.AlertChannel{
		Name: "mail", Type: alerts.ChannelEmail, Enabled: true,
		Config: `{"host":"smtp.example.com","from":"osctrl@example.com","to":"soc@example.com"}`,
	})
	require.NoError(t, err)
	setChannel := func(id uint) int {
		return santaDo(h.SantaConfigPutHandler, "PUT", "alice",
			fmt.Sprintf(`{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com","requester_channel":%d}`, id), p).Code
	}
	require.Equal(t, http.StatusBadRequest, setChannel(hook.ID))
	require.Equal(t, http.StatusBadRequest, setChannel(9999))
	require.Equal(t, http.StatusOK, setChannel(mail.ID))

	create := func(body string) map[string]string {
		t.Helper()
		rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", body, p)
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		var own SantaOwnRequest
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
		return map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}
	}
	deny := func(one map[string]string) {
		t.Helper()
		rr := santaDo(h.SantaRequestDecideHandler, "POST", "alice", `{"decision":"deny","reason":"not\nneeded"}`, one)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}

	// No email on the account: nothing is sent.
	deny(create(reqBody(sha, "first")))
	notifier.none(t)

	require.NoError(t, h.Users.ChangeEmail("dave", "dave@example.com"))
	deny(create(reqBody(sha, "second")))
	hit := notifier.next(t)
	require.Equal(t, []uint{mail.ID}, hit.Channels)
	require.Equal(t, "to:dave@example.com", hit.HistoryDetail)
	require.Equal(t, "Santa request denied", hit.RuleName)
	require.Contains(t, hit.Detail, "allowing tool (sha256 "+sha+")")
	require.Contains(t, hit.Detail, "was denied by alice. Reason: not needed")

	// MONITOR start, with its end time, and end.
	machine := strings.ToUpper(reqMachine)
	require.NoError(t, h.Santa.SaveMachine(&santa.Machine{EnvironmentID: 1, MachineID: machine}))
	one := create(fmt.Sprintf(`{"kind":"monitor","machine_id":%q,"hours":2,"justification":"debugging"}`, reqMachine))
	require.Equal(t, http.StatusOK, santaDo(h.SantaRequestDecideHandler, "POST", "alice", `{"decision":"approve"}`, one).Code)
	hit = notifier.next(t)
	require.Equal(t, "Santa request approved", hit.RuleName)
	require.Contains(t, hit.Detail, "MONITOR mode on machine "+machine+" was approved by alice")
	require.Contains(t, hit.Detail, "lasts until")
	gone, err := h.Santa.ExpireModeOverrides(time.Now().Add(3 * time.Hour))
	require.NoError(t, err)
	require.Len(t, gone, 1)
	h.SantaMonitorEnded(gone[0])
	hit = notifier.next(t)
	require.Equal(t, "Santa MONITOR mode ended", hit.RuleName)
	require.Equal(t, "to:dave@example.com", hit.HistoryDetail)

	// An admin's own MONITOR override has no requester to tell.
	o, err := h.Santa.GrantMonitor(1, machine, 1, "alice")
	require.NoError(t, err)
	h.SantaMonitorEnded(o)
	notifier.none(t)

	// Turned off: nothing is sent.
	require.Equal(t, http.StatusOK, setChannel(0))
	deny(create(reqBody(sha, "third")))
	notifier.none(t)
}
