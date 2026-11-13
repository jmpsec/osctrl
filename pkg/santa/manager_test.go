package santa

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := NewManager(db)
	require.NoError(t, err)
	return m
}

func testRule(env uint) *Rule {
	return &Rule{EnvironmentID: env, RuleType: "BINARY", Identifier: strings.Repeat("ab", 32), Policy: "BLOCKLIST", Scope: "env"}
}

func TestManagerConfigDefaultsAndSave(t *testing.T) {
	m := newTestManager(t)
	c, err := m.Config(1)
	require.NoError(t, err)
	require.Equal(t, "MONITOR", c.ClientMode)
	require.Equal(t, uint(1), c.EnvironmentID)

	_, err = m.RotateToken(1)
	require.NoError(t, err)
	before, _ := m.Config(1)
	require.NotEmpty(t, before.TokenHash)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", BatchSize: 10, TokenHash: "x"}))
	after, err := m.Config(1)
	require.NoError(t, err)
	require.Equal(t, "LOCKDOWN", after.ClientMode)
	require.Equal(t, uint32(10), after.BatchSize)
	require.Equal(t, before.TokenHash, after.TokenHash)
	require.Error(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "BOGUS"}))
}

func TestRotateTokenInvalidatesOld(t *testing.T) {
	m := newTestManager(t)
	t1, err := m.RotateToken(1)
	require.NoError(t, err)
	t2, err := m.RotateToken(1)
	require.NoError(t, err)
	require.False(t, m.CheckToken(1, t1))
	require.True(t, m.CheckToken(1, t2))
	require.False(t, m.CheckToken(2, t2))
	c, _ := m.Config(1)
	require.NotEqual(t, t1, c.TokenHash)
	require.NotEqual(t, t2, c.TokenHash)
}

func TestCheckTokenNoTokenConfigured(t *testing.T) {
	m := newTestManager(t)
	require.False(t, m.CheckToken(1, ""))
	require.False(t, m.CheckToken(1, "anything"))
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR"}))
	require.False(t, m.CheckToken(1, ""))
}

func TestDeleteRuleWrongEnv(t *testing.T) {
	m := newTestManager(t)
	r := testRule(1)
	require.NoError(t, m.CreateRule(r))
	require.ErrorIs(t, m.DeleteRule(2, r.ID), gorm.ErrRecordNotFound)
	rs, err := m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rs, 1)
	require.NoError(t, m.DeleteRule(1, r.ID))
}

func TestCreateRuleDuplicate(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.CreateRule(testRule(1)))
	require.ErrorIs(t, m.CreateRule(testRule(1)), ErrRuleExists)
	require.NoError(t, m.CreateRule(testRule(2)))
	bad := testRule(1)
	bad.Scope = ""
	require.ErrorIs(t, m.CreateRule(bad), ErrInvalidRule)
}

func TestManagerMachines(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Machine(1, "A")
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	mc := &Machine{EnvironmentID: 1, MachineID: "A", Hostname: "h"}
	require.NoError(t, m.SaveMachine(mc))
	mc.Hostname = "h2"
	require.NoError(t, m.SaveMachine(mc))
	got, err := m.Machine(1, "A")
	require.NoError(t, err)
	require.Equal(t, "h2", got.Hostname)
	all, err := m.Machines(1)
	require.NoError(t, err)
	require.Len(t, all, 1)
}

func TestAddEventsLarge(t *testing.T) {
	m := newTestManager(t)
	evs := make([]Event, 3000)
	for i := range evs {
		evs[i] = Event{EnvironmentID: 1, FileName: "f"}
	}
	require.NoError(t, m.AddEvents(evs))
	_, total, err := m.Events(1, 1, 1)
	require.NoError(t, err)
	require.Equal(t, int64(3000), total)
}

func TestEventsPagingAndPrune(t *testing.T) {
	m := newTestManager(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var evs []Event
	for i := 0; i < 5; i++ {
		evs = append(evs, Event{EnvironmentID: 1, FileName: string(rune('a' + i)), CreatedAt: base.Add(time.Duration(i) * time.Hour)})
	}
	require.NoError(t, m.AddEvents(evs))
	require.NoError(t, m.AddEvents(nil))
	page, total, err := m.Events(1, 1, 2)
	require.NoError(t, err)
	require.Equal(t, int64(5), total)
	require.Len(t, page, 2)
	require.Equal(t, "e", page[0].FileName)
	page, _, _ = m.Events(1, 3, 2)
	require.Len(t, page, 1)
	require.Equal(t, "a", page[0].FileName)
	_, _, err = m.Events(1, 1, 100000)
	require.NoError(t, err)

	n, err := m.PruneEvents(base.Add(2 * time.Hour))
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	_, total, _ = m.Events(1, 1, 10)
	require.Equal(t, int64(3), total)
}

func TestUpdateRule(t *testing.T) {
	m := newTestManager(t)
	r := testRule(1)
	r.CustomMsg = "old"
	r.CreatedBy = "alice"
	require.NoError(t, m.CreateRule(r))
	other := testRule(1)
	other.Identifier = strings.Repeat("cd", 32)
	require.NoError(t, m.CreateRule(other))
	digest := func() string {
		rs, err := m.EffectiveRules(1, "", nil)
		require.NoError(t, err)
		return RulesDigest(rs)
	}
	before := digest()

	// Normalizes like create, clears an emptied message, keeps CreatedBy.
	upd := *r
	upd.Identifier = strings.ToUpper(upd.Identifier)
	upd.Policy = "ALLOWLIST"
	upd.CustomMsg = ""
	require.NoError(t, m.UpdateRule(&upd))
	got, err := m.Rule(1, r.ID)
	require.NoError(t, err)
	require.Equal(t, r.Identifier, got.Identifier)
	require.Equal(t, "ALLOWLIST", got.Policy)
	require.Empty(t, got.CustomMsg)
	require.Equal(t, "alice", got.CreatedBy)
	require.NotEqual(t, before, digest(), "edit must change the digest so clients clean sync")

	dup := got
	dup.Identifier = other.Identifier
	require.ErrorIs(t, m.UpdateRule(&dup), ErrRuleExists)
	wrongEnv := got
	wrongEnv.EnvironmentID = 2
	require.ErrorIs(t, m.UpdateRule(&wrongEnv), gorm.ErrRecordNotFound)
	bad := got
	bad.Policy = "NOPE"
	require.ErrorIs(t, m.UpdateRule(&bad), ErrInvalidRule)
}
