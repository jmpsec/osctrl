package osqueryversions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type pn struct {
	uuid, host, local, version, platform string
	env                                  uint
	deleted                              bool
}

func addPN(t *testing.T, m *Manager, n pn) {
	t.Helper()
	row := behindNode{UUID: n.uuid, EnvironmentID: n.env, OsqueryVersion: n.version, Platform: n.platform, Hostname: n.host, Localname: n.local}
	if n.deleted {
		d := now
		row.DeletedAt = &d
	}
	require.NoError(t, m.db.Create(&row).Error)
}

func reject(t *testing.T, m *Manager, uuid string, env uint, reqID, reason string, at time.Time) {
	t.Helper()
	require.NoError(t, m.db.Create(&behindStatus{NodeUUID: uuid, EnvironmentID: env, UpgradeResult: "rejected",
		UpgradeReason: reason, UpgradeRequestID: reqID, UpgradeReportedAt: &at}).Error)
}

func rolloutWith(th [4]uint32, state string, stage int, opened time.Time) Rollout {
	b, _ := json.Marshal(th)
	return Rollout{EnvironmentID: 1, RequestID: "req1", Version: "5.13.0", State: state, Stage: stage, StageOpenedAt: opened, Thresholds: string(b)}
}

func progressFixture(t *testing.T) *Manager {
	m := newTestManager(t)
	require.NoError(t, m.db.AutoMigrate(&behindNode{}, &behindStatus{}))
	return m
}

func TestProgressCounts(t *testing.T) {
	m := progressFixture(t)
	// Ten nodes ordered by bucket: n0 has the smallest.
	type nb struct {
		uuid string
		b    uint32
	}
	var nbs []nb
	for i := 0; i < 10; i++ {
		u := fmt.Sprintf("N%d", i)
		nbs = append(nbs, nb{u, Bucket(1, "5.13.0", u)})
	}
	sort.Slice(nbs, func(i, j int) bool { return nbs[i].b < nbs[j].b })
	for i := 1; i < 10; i++ {
		require.NotEqual(t, nbs[i-1].b, nbs[i].b)
	}
	// rank 0..9 -> state: 0 upgraded, 1 waiting(old), 2 rolled back, 3 empty version,
	// 4 ahead, 5 old, 6 old, 7 windows old, 8 old, 9 old.
	ver := []string{"5.13.0", "5.12.1", "5.12.1", "", "5.14.0", "5.12.1", "5.12.1", "5.12.1", "5.12.1", "5.12.1"}
	for i, n := range nbs {
		p := "linux"
		if i == 7 {
			p = "windows"
		}
		addPN(t, m, pn{uuid: n.uuid, version: ver[i], env: 1, platform: p})
	}
	reject(t, m, nbs[2].uuid, 1, "req1", "version_not_reported", now)
	th := [4]uint32{nbs[2].b + 1, nbs[6].b + 1, nbs[8].b + 1, 10001}

	// Stage 1: ranks 0-2 eligible (upgraded, waiting, rolled back); rank 4 is upgraded but not eligible.
	p, err := m.Progress(rolloutWith(th, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCounts{Eligible: 3, Upgraded: 2, Waiting: 1, RolledBack: 1}, p.Counts) // rank 4 is upgraded but not eligible yet
	require.Equal(t, 0, p.Stage)
	require.Equal(t, RolloutRunning, p.State)
	require.NotNil(t, p.NextStageAt)

	// Stage 2 (one wait later): ranks 0-6 eligible; rank 7 windows never waiting.
	p, err = m.Progress(rolloutWith(th, RolloutRunning, 0, now.Add(-RolloutStageWait)), now)
	require.NoError(t, err)
	// Eligible ranks 0-6; the empty-version host (rank 3) counts as waiting.
	require.Equal(t, RolloutCounts{Eligible: 7, Upgraded: 2, Waiting: 4, RolledBack: 1}, p.Counts)
	require.Equal(t, 1, p.Stage)

	// Windows host is excluded entirely (Resolve answers unsupported_platform).
	p, err = m.Progress(rolloutWith(th, RolloutRunning, 0, now.Add(-3*RolloutStageWait)), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCompleted, p.State)
	require.Equal(t, RolloutCounts{Eligible: 9, Upgraded: 2, Waiting: 6, RolledBack: 1}, p.Counts)
	require.Nil(t, p.NextStageAt)

	// Paused freezes the stage.
	p, err = m.Progress(rolloutWith(th, RolloutPaused, 0, now.Add(-9*RolloutStageWait)), now)
	require.NoError(t, err)
	require.Equal(t, 3, p.Counts.Eligible)
	require.Equal(t, RolloutPaused, p.State)
}

func TestProgressIgnoresSoftDeletedAndOtherEnvironments(t *testing.T) {
	m := progressFixture(t)
	all := [4]uint32{10001, 10001, 10001, 10001}
	addPN(t, m, pn{uuid: "A", version: "5.12.1", env: 1, platform: "linux"})
	addPN(t, m, pn{uuid: "B", version: "5.12.1", env: 1, platform: "linux", deleted: true})
	addPN(t, m, pn{uuid: "C", version: "5.12.1", env: 2, platform: "linux"})
	reject(t, m, "B", 1, "req1", "x", now)
	reject(t, m, "C", 2, "req1", "x", now)
	p, err := m.Progress(rolloutWith(all, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCounts{Eligible: 1, Waiting: 1}, p.Counts)
	require.Empty(t, p.RolledBackHosts)
}

func TestProgressRolledBackOnlyForThisRequestID(t *testing.T) {
	m := progressFixture(t)
	addPN(t, m, pn{uuid: "A", version: "5.12.1", env: 1, platform: "linux"})
	addPN(t, m, pn{uuid: "B", version: "5.12.1", env: 1, platform: "linux"})
	reject(t, m, "A", 1, "other", "x", now)
	reject(t, m, "B", 1, "req1", "y", now)
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCounts{Eligible: 2, Waiting: 1, RolledBack: 1}, p.Counts)
	require.Len(t, p.RolledBackHosts, 1)
	require.Equal(t, "y", p.RolledBackHosts[0].Reason)
}

func TestProgressRolledBackHostsNewestFirstAndBounded(t *testing.T) {
	m := progressFixture(t)
	for i := 0; i < 60; i++ {
		u := fmt.Sprintf("H%02d", i)
		addPN(t, m, pn{uuid: u, version: "5.12.1", env: 1, platform: "linux", host: "host-" + u})
		reject(t, m, u, 1, "req1", "r", now.Add(time.Duration(i)*time.Minute))
	}
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, 60, p.Counts.RolledBack)
	require.Len(t, p.RolledBackHosts, 50)
	require.Equal(t, "host-H59", p.RolledBackHosts[0].Host)
	require.Equal(t, "host-H10", p.RolledBackHosts[49].Host)
}

func TestProgressEmptyEnvironment(t *testing.T) {
	m := progressFixture(t)
	p, err := m.Progress(rolloutWith([4]uint32{100, 1000, 5000, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCounts{}, p.Counts)
	require.Empty(t, p.RolledBackHosts)
}

func TestProgressHostNameFallback(t *testing.T) {
	m := progressFixture(t)
	addPN(t, m, pn{uuid: "A", version: "5.12.1", env: 1, platform: "linux", host: "h", local: "l"})
	addPN(t, m, pn{uuid: "B", version: "5.12.1", env: 1, platform: "linux", local: "l2"})
	addPN(t, m, pn{uuid: "C", version: "5.12.1", env: 1, platform: "linux"})
	for i, u := range []string{"A", "B", "C"} {
		reject(t, m, u, 1, "req1", "r", now.Add(time.Duration(i)*time.Minute))
	}
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	var hosts []string
	for _, h := range p.RolledBackHosts {
		hosts = append(hosts, h.Host)
	}
	require.Equal(t, []string{"C", "l2", "h"}, hosts)
}

func TestProgressNewestFiftyWithNullTimes(t *testing.T) {
	m := progressFixture(t)
	for i := 0; i < 55; i++ {
		u := fmt.Sprintf("H%02d", i)
		addPN(t, m, pn{uuid: u, version: "5.12.1", env: 1, platform: "linux", host: u})
		reject(t, m, u, 1, "req1", "r", now.Add(time.Duration(i)*time.Minute))
	}
	addPN(t, m, pn{uuid: "NULL", version: "5.12.1", env: 1, platform: "linux", host: "NULL"})
	require.NoError(t, m.db.Create(&behindStatus{NodeUUID: "NULL", EnvironmentID: 1, UpgradeResult: "rejected", UpgradeRequestID: "req1"}).Error)
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, 56, p.Counts.RolledBack)
	require.Len(t, p.RolledBackHosts, 50)
	require.Equal(t, "H54", p.RolledBackHosts[0].Host)
	require.Equal(t, "H05", p.RolledBackHosts[49].Host)
}

func TestProgressReasonTruncated(t *testing.T) {
	m := progressFixture(t)
	addPN(t, m, pn{uuid: "A", version: "5.12.1", env: 1, platform: "linux"})
	reject(t, m, "A", 1, "req1", strings.Repeat("x", 1000), now)
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Len(t, p.RolledBackHosts[0].Reason, 256)
}

func TestProgressRejectedEdgeCases(t *testing.T) {
	m := progressFixture(t)
	// U: upgraded and rejected; W: rejected Windows; O: rejected, outside stage 1.
	addPN(t, m, pn{uuid: "U", version: "5.13.0", env: 1, platform: "linux"})
	addPN(t, m, pn{uuid: "W", version: "5.12.1", env: 1, platform: "windows"})
	// O is the first fixture UUID whose bucket is above U's, so it is outside stage 1.
	o := ""
	for i := 0; o == ""; i++ {
		if c := fmt.Sprintf("O%d", i); Bucket(1, "5.13.0", c) > Bucket(1, "5.13.0", "U") {
			o = c
		}
	}
	addPN(t, m, pn{uuid: o, version: "5.12.1", env: 1, platform: "linux"})
	for _, u := range []string{"U", "W", o} {
		reject(t, m, u, 1, "req1", "r", now)
	}
	// Only U is eligible at stage 1.
	th := [4]uint32{Bucket(1, "5.13.0", "U") + 1, 0, 0, 10001}
	require.GreaterOrEqual(t, Bucket(1, "5.13.0", o), th[0])
	p, err := m.Progress(rolloutWith(th, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, RolloutCounts{Eligible: 1, Upgraded: 1, Waiting: 0, RolledBack: 2}, p.Counts)
	var hosts []string
	for _, h := range p.RolledBackHosts {
		hosts = append(hosts, h.Host)
	}
	require.ElementsMatch(t, []string{"U", o}, hosts)
}

func TestProgressHostNameCleaned(t *testing.T) {
	m := progressFixture(t)
	addPN(t, m, pn{uuid: "A", version: "5.12.1", env: 1, platform: "linux", host: "ev\nil\t", local: "l"})
	addPN(t, m, pn{uuid: "B", version: "5.12.1", env: 1, platform: "linux", host: "\n\t", local: "l2"})
	reject(t, m, "A", 1, "req1", "r", now)
	reject(t, m, "B", 1, "req1", "r", now.Add(-time.Minute))
	p, err := m.Progress(rolloutWith([4]uint32{10001, 10001, 10001, 10001}, RolloutRunning, 0, now), now)
	require.NoError(t, err)
	require.Equal(t, "evil", p.RolledBackHosts[0].Host)
	require.Equal(t, "l2", p.RolledBackHosts[1].Host, "falls back when the cleaned name is empty")
}

func TestCleanHost(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"plain":     {"web-1", "web-1"},
		"empty":     {"", ""},
		"newline":   {"a\nb\r\tc\x00d\x1b[0m", "abcd[0m"},
		"multibyte": {"héllo-日本", "héllo-日本"},
		"only ctrl": {"\n\t", ""},
		"oversized": {strings.Repeat("日", 300), strings.Repeat("日", 255)},
	} {
		t.Run(name, func(t *testing.T) { require.Equal(t, c.want, CleanHost(c.in)) })
	}
}
