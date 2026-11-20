package santa

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGrantMonitor(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	machine := strings.ToUpper(testUUID)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN"}))

	for name, hours := range map[string]uint{"zero hours": 0, "too long": MaxMonitorHours + 1} {
		_, err := m.GrantMonitor(1, machine, hours, "alice")
		require.ErrorIs(t, err, ErrInvalidOverride, name)
	}
	_, err := m.GrantMonitor(1, "nope", 1, "alice")
	require.ErrorIs(t, err, ErrInvalidOverride)
	_, err = m.GrantMonitor(1, machine, 1, "alice")
	require.ErrorIs(t, err, ErrUnknownMachine)

	require.NoError(t, m.SaveMachine(&Machine{EnvironmentID: 1, MachineID: machine}))
	o, err := m.grantMonitorIn(m.DB, 1, strings.ToLower(machine), 2, "alice", "dave")
	require.NoError(t, err)
	require.Equal(t, now.Add(2*time.Hour).Unix(), o.ExpiresAt.Unix())
	require.Equal(t, "dave", o.Requester)
	mode, source, err := m.EffectiveMode(1, machine, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"MONITOR", "node"}, []string{mode, source})

	// A new grant replaces the temporary override.
	o, err = m.GrantMonitor(1, machine, 1, "bob")
	require.NoError(t, err)
	require.Equal(t, "bob", o.CreatedBy)
	require.Empty(t, o.Requester, "a direct grant has no requester")
	require.Equal(t, now.Add(time.Hour).Unix(), o.ExpiresAt.Unix())

	// At expiry it stops applying, whether or not the sweep has run.
	now = now.Add(time.Hour)
	mode, source, err = m.EffectiveMode(1, machine, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"LOCKDOWN", "env"}, []string{mode, source})
	overrides, err := m.ModeOverrides(1)
	require.NoError(t, err)
	require.Empty(t, overrides)
	gone, err := m.ExpireModeOverrides(now)
	require.NoError(t, err)
	require.Len(t, gone, 1)
	require.Equal(t, machine, gone[0].ScopeValue)
	gone, err = m.ExpireModeOverrides(now)
	require.NoError(t, err)
	require.Empty(t, gone)

	// A permanent node override is never replaced, and a permanent set clears an expiry.
	require.NoError(t, m.SetModeOverride(&ModeOverride{EnvironmentID: 1, Scope: "node", ScopeValue: machine, ClientMode: "LOCKDOWN", CreatedBy: "alice"}))
	_, err = m.GrantMonitor(1, machine, 1, "alice")
	require.ErrorIs(t, err, ErrPermanentOverride)
	other := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, m.SaveMachine(&Machine{EnvironmentID: 1, MachineID: other}))
	_, err = m.GrantMonitor(1, other, 1, "alice")
	require.NoError(t, err)
	perm := ModeOverride{EnvironmentID: 1, Scope: "node", ScopeValue: other, ClientMode: "MONITOR", CreatedBy: "alice"}
	require.NoError(t, m.SetModeOverride(&perm))
	require.Nil(t, perm.ExpiresAt)
	gone, err = m.ExpireModeOverrides(now.Add(48 * time.Hour))
	require.NoError(t, err)
	require.Empty(t, gone)
}

func TestMonitorRequest(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	machine := strings.ToUpper(testUUID)

	tests := []struct {
		name, machine, why string
		hours              uint
		err                error
	}{
		{"bad machine", "nope", "why", 1, ErrInvalidRequest},
		{"no hours", machine, "why", 0, ErrInvalidRequest},
		{"too many hours", machine, "why", MaxMonitorHours + 1, ErrInvalidRequest},
		{"no justification", machine, " ", 1, ErrInvalidRequest},
		{"unknown machine", machine, "why", 1, ErrUnknownMachine},
	}
	for _, tt := range tests {
		_, _, err := m.CreateMonitorRequest(1, tt.machine, "bob", tt.why, tt.hours)
		require.ErrorIs(t, err, tt.err, tt.name)
	}
	require.NoError(t, m.SaveMachine(&Machine{EnvironmentID: 1, MachineID: machine}))
	req, created, err := m.CreateMonitorRequest(1, strings.ToLower(machine), "bob", "debugging a build", 4)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, RequestKindMonitor, req.Kind)
	again, created, err := m.CreateMonitorRequest(1, machine, "erin", "me too", 8)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, req.ID, again.ID)
	require.Contains(t, RequestNotice(req), "bob asks for MONITOR mode for 4 hours on machine "+machine)

	// Approval grants the hours from the approval, ignoring the rule scope.
	now = now.Add(30 * time.Minute)
	got, err := m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.NoError(t, err)
	require.Equal(t, RequestApproved, got.Status)
	require.Zero(t, got.RuleID)
	overrides, err := m.ModeOverrides(1)
	require.NoError(t, err)
	require.Len(t, overrides, 1)
	require.Equal(t, now.Add(4*time.Hour).Unix(), overrides[0].ExpiresAt.Unix())
	rules, err := m.Rules(1)
	require.NoError(t, err)
	require.Empty(t, rules)

	// A permanent override makes approval fail and leaves the request pending.
	req, _, err = m.CreateMonitorRequest(1, machine, "bob", "again", 1)
	require.NoError(t, err)
	require.NoError(t, m.SetModeOverride(&ModeOverride{EnvironmentID: 1, Scope: "node", ScopeValue: machine, ClientMode: "LOCKDOWN", CreatedBy: "alice"}))
	_, err = m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice"})
	require.ErrorIs(t, err, ErrPermanentOverride)
	pending, err := m.Request(1, req.ID)
	require.NoError(t, err)
	require.Equal(t, RequestPending, pending.Status)
	got, err = m.DecideRequest(1, req.ID, Decision{By: "alice", Reason: "use the permanent override"})
	require.NoError(t, err)
	require.Equal(t, RequestDenied, got.Status)
}
