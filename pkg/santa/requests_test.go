package santa

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateConfigApprovalURL(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{" https://osctrl.example.com/ ", "https://osctrl.example.com", true},
		{"https://osctrl.example.com/ui", "https://osctrl.example.com/ui", true},
		{"http://osctrl.example.com", "", false},
		{"https://", "", false},
		{"https://user@osctrl.example.com", "", false},
		{"https://osctrl.example.com/?x=1", "", false},
		{"https://osctrl.example.com/#frag", "", false},
		{"https://osctrl.example.com/%username%", "", false},
		{"javascript:alert(1)", "", false},
		{"https://osctrl.example.com/" + strings.Repeat("a", 250), "", false},
	}
	for _, tt := range tests {
		c := EnvConfig{ClientMode: "MONITOR", ApprovalURL: tt.in}
		err := ValidateConfig(&c)
		if !tt.ok {
			require.Error(t, err, tt.in)
			continue
		}
		require.NoError(t, err, tt.in)
		require.Equal(t, tt.want, c.ApprovalURL)
	}
}

func TestPreflightEventDetailURL(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	n.EnvUUID = "env uuid"
	resp := mustPreflight(t, m, n, false)
	require.False(t, resp.HasEventDetailUrl(), "off by default")

	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com/"}))
	resp = mustPreflight(t, m, n, false)
	require.Equal(t, "https://osctrl.example.com/santa/request/env%20uuid?sha256=%file_sha%&machine_id=%machine_id%", resp.GetEventDetailUrl())
	require.Equal(t, "Request approval", resp.GetEventDetailText())

	// Saving the config without the URL turns the link off again.
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN"}))
	require.False(t, mustPreflight(t, m, n, false).HasEventDetailUrl())
}

func TestCreateRequest(t *testing.T) {
	m := newTestManager(t)
	sha := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	machine := strings.ToUpper(testUUID)
	require.NoError(t, m.AddEvents([]Event{
		{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_UNKNOWN", FileSHA256: sha, FileName: "tool", FilePath: "/tmp", SigningID: "sid"},
		{EnvironmentID: 1, MachineID: machine, Decision: "ALLOW_BINARY", FileSHA256: other},
		{EnvironmentID: 2, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: other},
	}))

	bad := []struct{ name, machine, sha, who, why string }{
		{"machine not a uuid", "M-1", sha, "bob", "need it"},
		{"short hash", machine, "abcd", "bob", "need it"},
		{"blank justification", machine, sha, "bob", "  "},
		{"long justification", machine, sha, "bob", strings.Repeat("é", MaxJustification+1)},
		{"no requester", machine, sha, "", "need it"},
	}
	for _, tt := range bad {
		_, _, err := m.CreateRequest(1, tt.machine, tt.sha, tt.who, tt.why)
		require.ErrorIs(t, err, ErrInvalidRequest, tt.name)
	}
	// Allowed here, blocked only in another environment, never seen: no request.
	for _, s := range []string{other, strings.Repeat("ef", 32)} {
		_, _, err := m.CreateRequest(1, machine, s, "bob", "need it")
		require.ErrorIs(t, err, ErrNoBlockedEvent)
	}

	req, created, err := m.CreateRequest(1, strings.ToLower(machine), strings.ToUpper(sha), "bob", " need it ")
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, RequestPending, req.Status)
	require.Equal(t, "need it", req.Justification)
	require.Equal(t, "tool", req.FileName)
	require.Equal(t, "sid", req.SigningID)
	require.NotZero(t, req.EventID)
	// The limit counts characters, not bytes.
	_, _, err = m.CreateRequest(1, machine, sha, "bob", strings.Repeat("é", MaxJustification))
	require.NoError(t, err)

	// The same file and machine merge into the pending request, whoever asks.
	for _, who := range []string{"bob", "eve"} {
		again, created, err := m.CreateRequest(1, machine, sha, who, "me too")
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, req.ID, again.ID)
		require.Equal(t, "need it", again.Justification)
	}
	all, err := m.Requests(1, "", "")
	require.NoError(t, err)
	require.Len(t, all, 1)
	mine, err := m.Requests(1, "", "eve")
	require.NoError(t, err)
	require.Empty(t, mine)
	inOther, err := m.Requests(2, "", "")
	require.NoError(t, err)
	require.Empty(t, inOther)

	// Expiry only touches old pending requests; a decided file can be asked for again.
	n, err := m.ExpireRequests(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = m.ExpireRequests(time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	expired, err := m.Requests(1, RequestExpired, "")
	require.NoError(t, err)
	require.Len(t, expired, 1)
	_, created, err = m.CreateRequest(1, machine, sha, "eve", "again")
	require.NoError(t, err)
	require.True(t, created)
}

func TestCreateRequestPendingCap(t *testing.T) {
	m := newTestManager(t)
	machine := strings.ToUpper(testUUID)
	evs := make([]Event, MaxPendingRequests+1)
	for i := range evs {
		evs[i] = Event{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: fmt.Sprintf("%064x", i)}
	}
	require.NoError(t, m.AddEvents(evs))
	for i := 0; i < MaxPendingRequests; i++ {
		_, _, err := m.CreateRequest(1, machine, evs[i].FileSHA256, "bob", "need it")
		require.NoError(t, err)
	}
	_, _, err := m.CreateRequest(1, machine, evs[MaxPendingRequests].FileSHA256, "bob", "need it")
	require.ErrorIs(t, err, ErrTooManyRequests)
	// The cap is per requester.
	_, _, err = m.CreateRequest(1, machine, evs[MaxPendingRequests].FileSHA256, "eve", "need it")
	require.NoError(t, err)
}
