package osqueryversions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Minimal stand-ins for the nodes and osctrld status tables (their real
// models live in packages this one must not import).
type behindNode struct {
	ID             uint `gorm:"primaryKey"`
	UUID           string
	EnvironmentID  uint
	OsqueryVersion string
	Platform       string
	DeletedAt      *time.Time
}

func (behindNode) TableName() string { return "osquery_nodes" }

type behindStatus struct {
	ID            uint `gorm:"primaryKey"`
	NodeUUID      string
	EnvironmentID uint
	ReportedAt    *time.Time
}

func (behindStatus) TableName() string { return "node_osctrld_status" }

const fresh = 15 * time.Minute

func behindFixture(t *testing.T) *Manager {
	t.Helper()
	m := libWithTarget(t) // env 1 target 5.13.0
	require.NoError(t, m.db.AutoMigrate(&behindNode{}, &behindStatus{}))
	return m
}

func addNode(t *testing.T, m *Manager, uuid string, env uint, version string, reported time.Time) {
	t.Helper()
	require.NoError(t, m.db.Create(&behindNode{UUID: uuid, EnvironmentID: env, OsqueryVersion: version}).Error)
	require.NoError(t, m.db.Create(&behindStatus{NodeUUID: uuid, EnvironmentID: env, ReportedAt: &reported}).Error)
}

func TestCountBehindUsesPinOverEnvironment(t *testing.T) {
	m := behindFixture(t) // env 1 target 5.13.0
	seed(t, m, "5.12.2", deb(digestA))
	seed(t, m, "5.14.0", deb(digestB))
	at := time.Now().Add(2 * time.Hour) // evaluation time: c's pin has expired by then
	addNode(t, m, "a", 1, "5.12.1", at) // behind the environment target
	addNode(t, m, "b", 1, "5.12.1", at) // pinned to what it runs: not behind
	addNode(t, m, "c", 1, "5.12.1", at) // expired pin: environment target applies
	addNode(t, m, "d", 1, "5.12.1", at) // other environment's pin is ignored
	addNode(t, m, "e", 2, "5.12.1", at) // environment without target
	addNode(t, m, "f", 1, "5.13.0", at) // at the environment target, pinned higher
	for _, p := range []struct {
		uuid string
		env  uint
		ver  string
		in   time.Duration
	}{{"b", 1, "5.12.1", 3 * time.Hour}, {"c", 1, "5.12.2", time.Hour}, {"d", 2, "5.12.1", 3 * time.Hour}, {"f", 1, "5.14.0", 3 * time.Hour}} {
		exp := time.Now().Add(p.in)
		_, err := m.SetPin(p.uuid, p.env, p.ver, &exp, "x")
		require.NoError(t, err)
	}
	got, err := m.CountBehind(at, fresh)
	require.NoError(t, err)
	require.Equal(t, map[uint]int{1: 4}, got) // a, c, d, f
}

func TestCountBehindIgnoresStaleReportsAndNoTarget(t *testing.T) {
	m := behindFixture(t)
	addNode(t, m, "a", 1, "5.12.1", now.Add(-2*fresh)) // stale
	addNode(t, m, "b", 2, "5.12.1", now)               // no target
	addNode(t, m, "c", 1, "5.13.0", now)               // at target
	addNode(t, m, "d", 1, "5.14.0", now)               // ahead
	got, err := m.CountBehind(now, fresh)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestCountBehindIgnoresUnparseableVersions(t *testing.T) {
	m := behindFixture(t)
	addNode(t, m, "a", 1, "", now)
	addNode(t, m, "b", 1, "garbage", now)
	addNode(t, m, "c", 1, "5.12.1", now)
	got, err := m.CountBehind(now, fresh)
	require.NoError(t, err)
	require.Equal(t, map[uint]int{1: 1}, got)
}

// Enrolling into another environment leaves the old node row behind, while
// node_osctrld_status keeps one row per UUID: the stale row must not join the
// fresh report of the new environment.
func TestCountBehindJoinsOnEnvironment(t *testing.T) {
	m := behindFixture(t) // env 1 target 5.13.0
	_, err := m.SetEnvTarget(2, "5.13.0", "admin")
	require.NoError(t, err)
	require.NoError(t, m.db.Create(&behindNode{UUID: "h", EnvironmentID: 1, OsqueryVersion: "5.12.1"}).Error) // stale row, env 1
	addNode(t, m, "h", 2, "5.12.1", now)                                                                      // current row and report, env 2
	got, err := m.CountBehind(now, fresh)
	require.NoError(t, err)
	require.Equal(t, map[uint]int{2: 1}, got)
}

// osctrld does not upgrade Windows hosts, so they are never counted behind.
func TestCountBehindExcludesWindows(t *testing.T) {
	m := behindFixture(t) // env 1 target 5.13.0
	for _, n := range []struct{ uuid, platform string }{{"w1", "windows"}, {"w2", "Windows"}, {"l", "ubuntu"}} {
		require.NoError(t, m.db.Create(&behindNode{UUID: n.uuid, EnvironmentID: 1, OsqueryVersion: "5.12.1", Platform: n.platform}).Error)
		require.NoError(t, m.db.Create(&behindStatus{NodeUUID: n.uuid, EnvironmentID: 1, ReportedAt: &now}).Error)
	}
	got, err := m.CountBehind(now, fresh)
	require.NoError(t, err)
	require.Equal(t, map[uint]int{1: 1}, got)
}
