package vulns

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newTestWorker also creates osquery_nodes: the first tick runs housekeeping,
// which sweeps rows of nodes that are not there.
func newTestWorker(t *testing.T, db *gorm.DB, baseURL string, clock *fixedClock) *Worker {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	w, err := NewWorker(db, Config{
		OSVURL: baseURL, KEVURL: baseURL + "/kev.json",
		SyncInterval: 6 * time.Hour, Retention: 90 * 24 * time.Hour,
		MaxDownload: 10 << 20, HTTPClient: http.DefaultClient,
	})
	require.NoError(t, err)
	w.now = clock.now
	return w
}

func TestLeaseIsHeldByOneWorkerUntilItExpires(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	a := newTestWorker(t, db, "http://unused", clock)
	b := newTestWorker(t, db, "http://unused", clock)

	ok, err := a.acquireLease()
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = b.acquireLease()
	require.NoError(t, err)
	assert.False(t, ok, "a live lease excludes other replicas")
	ok, _ = a.acquireLease()
	assert.True(t, ok, "the holder renews")

	clock.advance(leaseTTL + time.Second)
	ok, err = b.acquireLease()
	require.NoError(t, err)
	assert.True(t, ok, "a crashed holder's lease expires")
}

func TestNewWorkerRejectsNonHTTPFeedURLs(t *testing.T) {
	_, err := NewWorker(newTestDB(t), Config{OSVURL: "file:///etc", KEVURL: DefaultKEVURL})
	assert.Error(t, err)
}

func TestParseEcosystems(t *testing.T) {
	assert.Equal(t, []string{"Debian", "Red Hat"}, ParseEcosystems(" Debian, ,Red Hat "))
	assert.Nil(t, ParseEcosystems(""))
}

// End to end: a node reports Debian packages, one tick downloads the Debian
// feed and KEV, and the node has a KEV-flagged finding.
func TestTickSyncsMatchesAndFlags(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-DSA-1-1"}]}`))
	db := newTestDB(t)
	clock := newClock()
	inv := &Inventory{DB: db, now: clock.now}
	require.NoError(t, inv.ingestSnapshot("N1", 1, CategoryOS, []byte(`[{"platform":"debian","version":"12 (bookworm)","major":"12"}]`)))
	require.NoError(t, inv.ingestSnapshot("N1", 1, CategoryDeb, []byte(`[{"name":"libssl3","source":"openssl","version":"3.0.11-1"}]`)))
	w := newTestWorker(t, db, srv.URL, clock)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "N1"}).Error, "an enrolled node, or housekeeping sweeps its rows")

	clock.advance(time.Second)
	require.NoError(t, w.Tick(context.Background()))

	var got []Finding
	require.NoError(t, db.Find(&got).Error)
	require.Len(t, got, 1)
	assert.True(t, got[0].KEV)
	assert.Equal(t, "openssl", got[0].Package)
	assert.Zero(t, fs.hitCount("/PyPI/all.zip"), "only ecosystems the fleet reports are downloaded")
}

func TestSyncSchedule(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	w := newTestWorker(t, db, srv.URL, clock)

	require.NoError(t, w.Tick(context.Background()))
	require.Equal(t, 1, fs.hitCount("/kev.json"), "the first tick syncs")
	clock.advance(time.Hour)
	require.NoError(t, w.Tick(context.Background()))
	assert.Equal(t, 1, fs.hitCount("/kev.json"), "nothing is due an hour later")

	require.NoError(t, RequestSync(db, clock.now()))
	require.NoError(t, w.Tick(context.Background()))
	assert.Equal(t, 2, fs.hitCount("/kev.json"), "sync-now runs on the next tick")

	fs.fail("/kev.json", http.StatusBadGateway)
	clock.advance(6 * time.Hour)
	require.NoError(t, w.Tick(context.Background()))
	assert.Equal(t, 3, fs.hitCount("/kev.json"))
	clock.advance(failureRetry)
	require.NoError(t, w.Tick(context.Background()))
	assert.Equal(t, 4, fs.hitCount("/kev.json"), "a failed sync is retried after the short retry interval")
}

// An ecosystem that first appears in the fleet after a sync is fetched
// without waiting for the next full interval.
func TestNewEcosystemSyncsWithoutWaitingForTheInterval(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	fs.set("/PyPI/all.zip", zipOf(t, map[string]string{}))
	db := newTestDB(t)
	clock := newClock()
	w := newTestWorker(t, db, srv.URL, clock)
	require.NoError(t, w.Tick(context.Background()))

	inv := &Inventory{DB: db, now: clock.now}
	require.NoError(t, inv.ingestSnapshot("N1", 1, CategoryPython, []byte(`[{"name":"requests","version":"2.31.0"}]`)))
	clock.advance(failureRetry)
	require.NoError(t, w.Tick(context.Background()))
	assert.Equal(t, 1, fs.hitCount("/PyPI/all.zip"))
}

func TestHousekeepingSweepsDeletedNodesAndOldResolvedFindings(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "LIVE"}).Error)
	clock := newClock()
	old := clock.now().Add(-100 * 24 * time.Hour)
	recent := clock.now().Add(-time.Hour)
	for _, uuid := range []string{"LIVE", "GONE"} {
		require.NoError(t, db.Create(&NodeSoftware{NodeUUID: uuid, Category: CategoryDeb, Name: "a", Version: "1"}).Error)
		require.NoError(t, db.Create(&NodeState{NodeUUID: uuid}).Error)
	}
	require.NoError(t, db.Create(&Finding{NodeUUID: "LIVE", AdvisoryID: "A1", Ecosystem: "e", Package: "p1", ResolvedAt: &old}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "LIVE", AdvisoryID: "A2", Ecosystem: "e", Package: "p2", ResolvedAt: &recent}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "LIVE", AdvisoryID: "A3", Ecosystem: "e", Package: "p3"}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "GONE", AdvisoryID: "A1", Ecosystem: "e", Package: "p1"}).Error)

	w := newTestWorker(t, db, "http://unused", clock)
	require.NoError(t, w.housekeep())

	var ids []string
	require.NoError(t, db.Model(&Finding{}).Order("advisory_id").Pluck("advisory_id", &ids).Error)
	assert.Equal(t, []string{"A2", "A3"}, ids)
	var n int64
	db.Model(&NodeSoftware{}).Where("node_uuid = ?", "GONE").Count(&n)
	assert.Zero(t, n)
	db.Model(&NodeState{}).Where("node_uuid = ?", "GONE").Count(&n)
	assert.Zero(t, n)
}
