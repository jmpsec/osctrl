package changes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m, err := NewManager(db)
	require.NoError(t, err)
	return m
}

func TestGateLifecycle(t *testing.T) {
	m := newTestManager(t)
	body := []byte(`{"client_mode":"MONITOR"}`)
	gate := func(user string, b []byte) (Change, bool) {
		c, created, err := m.Gate(1, user, "update config", "PUT", "/api/v1/santa/dev/config", b)
		require.NoError(t, err)
		return c, created
	}

	c, created := gate("alice", body)
	require.True(t, created)
	require.Equal(t, StatusPending, c.Status)

	// Sending it again while pending returns the same change.
	again, created := gate("alice", body)
	require.False(t, created)
	require.Equal(t, c.ID, again.ID)
	require.Equal(t, StatusPending, again.Status)

	_, err := m.Decide(1, c.ID, "alice", true)
	require.ErrorIs(t, err, ErrSelfApproval)
	_, err = m.Decide(2, c.ID, "bob", true)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "another environment")

	d, err := m.Decide(1, c.ID, "bob", true)
	require.NoError(t, err)
	require.Equal(t, StatusApproved, d.Status)
	_, err = m.Decide(1, c.ID, "carol", false)
	require.ErrorIs(t, err, ErrNotPending)

	// The approval is the requester's, for this exact request only.
	_, created = gate("bob", body)
	require.True(t, created, "another user gets a new pending change")
	_, created = gate("alice", []byte(`{"client_mode":"LOCKDOWN"}`))
	require.True(t, created, "a different body is a different change")

	used, _ := gate("alice", body)
	require.Equal(t, c.ID, used.ID)
	require.Equal(t, StatusApplied, used.Status)

	// One use: the next identical request needs a new approval.
	next, created := gate("alice", body)
	require.True(t, created)
	require.NotEqual(t, c.ID, next.ID)
}

func TestDecideDenyAndExpiry(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	c, _, err := m.Gate(1, "alice", "rotate token", "POST", "/t", nil)
	require.NoError(t, err)

	// The requester can withdraw their own change.
	d, err := m.Decide(1, c.ID, "alice", false)
	require.NoError(t, err)
	require.Equal(t, StatusDenied, d.Status)

	c, _, err = m.Gate(1, "alice", "rotate token", "POST", "/t", nil)
	require.NoError(t, err)
	require.Equal(t, StatusPending, c.Status)
	_, err = m.Decide(1, c.ID, "bob", true)
	require.NoError(t, err)

	// An approval not used within the TTL expires.
	now = now.Add(TTL + time.Minute)
	list, err := m.List(1)
	require.NoError(t, err)
	require.Equal(t, StatusExpired, list[0].Status)
	late, created, err := m.Gate(1, "alice", "rotate token", "POST", "/t", nil)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, StatusPending, late.Status)

	// A pending change past the TTL cannot be approved.
	now = now.Add(TTL + time.Minute)
	_, err = m.Decide(1, late.ID, "bob", true)
	require.ErrorIs(t, err, ErrNotPending)

	n, err := m.Prune(now)
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
}
