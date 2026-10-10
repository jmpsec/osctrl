package vulns

import (
	"context"
	"net/http"
	"os"
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

func newTestWorkerNVD(t *testing.T, db *gorm.DB, baseURL string, clock *fixedClock) *Worker {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	w, err := NewWorker(db, Config{
		OSVURL: baseURL, KEVURL: baseURL + "/kev.json", NVDEnabled: true, NVDURL: baseURL + "/nvd",
		SyncInterval: 6 * time.Hour, Retention: 90 * 24 * time.Hour,
		MaxDownload: 10 << 20, HTTPClient: http.DefaultClient,
	})
	require.NoError(t, err)
	w.now = clock.now
	return w
}

func TestNewWorkerValidatesTheNVDURLOnlyWhenEnabled(t *testing.T) {
	_, err := NewWorker(newTestDB(t), Config{OSVURL: DefaultOSVURL, KEVURL: DefaultKEVURL, NVDEnabled: true, NVDURL: "file:///etc/passwd"})
	assert.Error(t, err)
	_, err = NewWorker(newTestDB(t), Config{OSVURL: DefaultOSVURL, KEVURL: DefaultKEVURL, NVDURL: "file:///etc/passwd"})
	assert.NoError(t, err, "ignored while NVD is off")
}

// End to end: a Windows node reports Firefox, one tick syncs NVD and KEV, and
// the node has a possible, KEV-flagged finding.
func TestTickMatchesWindowsProgramsAgainstNVD(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-1000"}]}`))
	fs.set("/nvd", []byte(nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`))))
	db := newTestDB(t)
	clock := newClock()
	inv := &Inventory{DB: db, now: clock.now}
	require.NoError(t, inv.ingestSnapshot("W1", 1, CategoryOS, []byte(`[{"platform":"windows","version":"10.0.22631","major":"10"}]`)))
	require.NoError(t, inv.ingestSnapshot("W1", 1, CategoryPrograms, []byte(`[{"name":"Mozilla Firefox (x64 en-US)","version":"128.0.3","publisher":"Mozilla"}]`)))
	w := newTestWorkerNVD(t, db, srv.URL, clock)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "W1"}).Error)

	clock.advance(time.Second)
	require.NoError(t, w.Tick(context.Background()))

	var got []Finding
	require.NoError(t, db.Find(&got).Error)
	require.Len(t, got, 1)
	assert.Equal(t, ConfidencePossible, got[0].Confidence)
	assert.Equal(t, "mozilla:firefox", got[0].Package)
	assert.Equal(t, "130.0", got[0].FixedVersion)
	assert.True(t, got[0].KEV)
	var ws WorkerState
	require.NoError(t, db.First(&ws, "name = ?", workerName).Error)
	assert.NotNil(t, ws.NVDActiveAt, "an NVD replica says so, for replicas with NVD off")
}

// Turning NVD on syncs it at the next retry point, not hours later.
func TestNVDSyncsSoonAfterItIsTurnedOn(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	w := newTestWorkerNVD(t, db, "http://unused", clock)
	last := clock.now().Add(-failureRetry)
	due, err := w.syncDue(WorkerState{LastSyncAt: &last}, nil)
	require.NoError(t, err)
	assert.True(t, due)
	now := clock.now()
	require.NoError(t, recordSuccess(db, sourceNVD, now, SyncResult{}, now))
	due, err = w.syncDue(WorkerState{LastSyncAt: &last}, nil)
	require.NoError(t, err)
	assert.False(t, due)
}

// Turning NVD off removes what it left: possible findings resolve, borrowed
// severities revert, and its sync row stops marking data stale.
func TestTurningNVDOffDropsItsData(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	require.NoError(t, recordSuccess(db, sourceNVD, now, SyncResult{}, now))
	require.NoError(t, db.Create(&[]Advisory{
		{ID: "CVE-2026-1000", Source: AdvisorySourceNVD, Severity: SeverityCritical, CVSSVector: cvss98, CVSSScore: 9.8},
		{ID: "DSA-1-1", Source: AdvisorySourceOSV, Severity: SeverityCritical, CVSSVector: cvss98, CVSSScore: 9.8, CVSSFrom: "CVE-2026-1000"},
	}).Error)
	require.NoError(t, db.Create(&[]Alias{
		{AdvisoryID: "CVE-2026-1000", Alias: "CVE-2026-1000"}, {AdvisoryID: "DSA-1-1", Alias: "CVE-2026-1000"},
	}).Error)
	require.NoError(t, db.Create(&Affected{AdvisoryID: "CVE-2026-1000", Ecosystem: cpeEcosystem, Package: "mozilla:firefox", Ranges: "[]", Versions: "[]"}).Error)
	require.NoError(t, db.Create(&CPEProduct{Vendor: "mozilla", Product: "firefox"}).Error)
	require.NoError(t, db.Create(&NodeState{NodeUUID: "W1", EnvironmentID: 1, InventoryAt: now, MatchedAt: &now}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "W1", EnvironmentID: 1, AdvisoryID: "CVE-2026-1000", Ecosystem: cpeEcosystem,
		Package: "mozilla:firefox", Severity: SeverityCritical, Confidence: ConfidencePossible}).Error)
	w := newTestWorker(t, db, srv.URL, clock) // NVD off
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "W1"}).Error)

	clock.advance(time.Second)
	require.NoError(t, w.Tick(context.Background()))

	var n int64
	require.NoError(t, db.Model(&SyncState{}).Where("source = ?", sourceNVD).Count(&n).Error)
	assert.Zero(t, n, "a feed that will never sync again must not mark data stale")
	require.NoError(t, db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD).Count(&n).Error)
	assert.Zero(t, n)
	require.NoError(t, db.Model(&Affected{}).Where("ecosystem = ?", cpeEcosystem).Count(&n).Error)
	assert.Zero(t, n)
	require.NoError(t, db.Model(&CPEProduct{}).Count(&n).Error)
	assert.Zero(t, n)
	var dsa Advisory
	require.NoError(t, db.First(&dsa, "id = ?", "DSA-1-1").Error)
	assert.Equal(t, SeverityUnknown, dsa.Severity)
	assert.Empty(t, dsa.CVSSFrom)
	var f Finding
	require.NoError(t, db.First(&f, "node_uuid = ?", "W1").Error)
	assert.NotNil(t, f.ResolvedAt, "the node was re-matched and the possible finding resolved")
}

// A sync that runs long and fails waits the retry interval after it ends,
// not after it started: otherwise it reruns at once and matching starves.
func TestFailedLongSyncWaitsBeforeRetrying(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	fs.fail("/nvd", http.StatusServiceUnavailable)
	db := newTestDB(t)
	clock := newClock()
	w := newTestWorkerNVD(t, db, srv.URL, clock)
	// Each retry wait takes 10 minutes: the failing sync lasts 20.
	w.nvd.sleep = func(_ context.Context, d time.Duration) error {
		clock.advance(10 * time.Minute)
		return nil
	}
	require.NoError(t, w.Tick(context.Background()))

	var ws WorkerState
	require.NoError(t, db.First(&ws, "name = ?", workerName).Error)
	require.True(t, ws.LastSyncFailed)
	due, err := w.syncDue(ws, nil)
	require.NoError(t, err)
	assert.False(t, due, "retry 15 minutes after the failure, not straight away")
	clock.advance(failureRetry)
	due, err = w.syncDue(ws, nil)
	require.NoError(t, err)
	assert.True(t, due)
}

// An interrupted first sync can leave NVD data without a sync row, and nodes
// silent for 30 days are never re-matched: neither may keep NVD effects once
// NVD is off.
func TestDropNVDCleansUpWithoutASyncRowAndOnStaleNodes(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	stale := clock.now().Add(-40 * 24 * time.Hour)
	require.NoError(t, db.Create(&[]Advisory{
		{ID: "CVE-2026-1000", Source: AdvisorySourceNVD, Severity: SeverityCritical, CVSSVector: cvss98, CVSSScore: 9.8},
		{ID: "DSA-1-1", Source: AdvisorySourceOSV, Severity: SeverityCritical, CVSSVector: cvss98, CVSSScore: 9.8, CVSSFrom: "CVE-2026-1000"},
	}).Error)
	require.NoError(t, db.Create(&Alias{AdvisoryID: "DSA-1-1", Alias: "CVE-2026-1000"}).Error)
	require.NoError(t, db.Create(&CPEProduct{Vendor: "mozilla", Product: "firefox"}).Error)
	require.NoError(t, db.Create(&NodeState{NodeUUID: "OLD", EnvironmentID: 1, InventoryAt: stale, MatchedAt: &stale}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "OLD", EnvironmentID: 1, AdvisoryID: "CVE-2026-1000", Ecosystem: cpeEcosystem,
		Package: "mozilla:firefox", Severity: SeverityCritical, Confidence: ConfidencePossible}).Error)

	require.NoError(t, dropNVD(db, clock.now()))

	var n int64
	require.NoError(t, db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD).Count(&n).Error)
	assert.Zero(t, n, "NVD data without a sync row is dropped too")
	require.NoError(t, db.Model(&CPEProduct{}).Count(&n).Error)
	assert.Zero(t, n)
	dsa := advisoryByID(t, db, "DSA-1-1")
	assert.Equal(t, SeverityUnknown, dsa.Severity)
	assert.Empty(t, dsa.CVSSFrom)
	var f Finding
	require.NoError(t, db.First(&f, "node_uuid = ?", "OLD").Error)
	assert.NotNil(t, f.ResolvedAt, "a stale node's possible finding resolves without a re-match")
}

func TestHousekeepingPrunesOldEscalations(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	w := newTestWorker(t, db, "http://unused", clock)
	require.NoError(t, db.Create(&[]Escalation{
		{FindingID: 1, CreatedAt: clock.now().Add(-31 * 24 * time.Hour)},
		{FindingID: 2, CreatedAt: clock.now()},
	}).Error)
	require.NoError(t, w.housekeep())
	var n int64
	require.NoError(t, db.Model(&Escalation{}).Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

// Replicas that disagree on --vuln-nvd-enabled must not delete NVD data on
// every lease handover: an NVD-off replica keeps it while another replica
// used NVD within nvdDropAfter.
func TestNVDDataSurvivesAReplicaWithNVDOff(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	require.NoError(t, recordSuccess(db, sourceNVD, now, SyncResult{}, now))
	require.NoError(t, db.Create(&Advisory{ID: "CVE-2026-1000", Source: AdvisorySourceNVD, Severity: SeverityHigh}).Error)
	require.NoError(t, db.Create(&WorkerState{Name: workerName, NVDActiveAt: &now, NVDActiveBy: "other-replica"}).Error)
	w := newTestWorker(t, db, srv.URL, clock) // NVD off

	clock.advance(time.Minute)
	require.NoError(t, w.Tick(context.Background()))
	var n int64
	require.NoError(t, db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD).Count(&n).Error)
	assert.Equal(t, int64(1), n, "another replica used NVD a minute ago")

	clock.advance(nvdDropAfter)
	require.NoError(t, w.Tick(context.Background()))
	require.NoError(t, db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD).Count(&n).Error)
	assert.Zero(t, n, "no replica has used NVD for an hour")
}

// One osctrl-api restarted with NVD off is not "another replica": its own
// earlier stamp does not delay the drop.
func TestTurningNVDOffOnTheSameHostDropsAtOnce(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	host, _ := os.Hostname()
	require.NoError(t, recordSuccess(db, sourceNVD, now, SyncResult{}, now))
	require.NoError(t, db.Create(&Advisory{ID: "CVE-2026-1000", Source: AdvisorySourceNVD, Severity: SeverityHigh}).Error)
	require.NoError(t, db.Create(&WorkerState{Name: workerName, NVDActiveAt: &now, NVDActiveBy: host}).Error)
	w := newTestWorker(t, db, srv.URL, clock)
	clock.advance(time.Minute)
	require.NoError(t, w.Tick(context.Background()))
	var n int64
	require.NoError(t, db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD).Count(&n).Error)
	assert.Zero(t, n)
}

// A feed the fleet no longer uses never syncs again: its row would mark every
// view stale and export a frozen last-success time. The sync drops it.
func TestSyncDropsFeedsNoLongerInUse(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	require.NoError(t, recordSuccess(db, "osv:Ubuntu", now, SyncResult{}, now))
	inv := &Inventory{DB: db, now: clock.now}
	require.NoError(t, inv.ingestSnapshot("N1", 1, CategoryOS, []byte(`[{"platform":"debian","version":"12 (bookworm)","major":"12"}]`)))
	w := newTestWorker(t, db, srv.URL, clock)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "N1"}).Error)
	clock.advance(time.Second)
	require.NoError(t, w.Tick(context.Background()))
	var sources []string
	require.NoError(t, db.Model(&SyncState{}).Order("source").Pluck("source", &sources).Error)
	assert.Equal(t, []string{sourceKEV, "osv:Debian"}, sources)
}

// Only feeds no node reports are dropped. An ecosystem the allow-list leaves
// out but the fleet still runs keeps its row (its findings stay matched), and
// an empty fleet drops nothing (re-adding a node must not re-download).
func TestSyncKeepsFeedsTheFleetStillReports(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}`))
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	require.NoError(t, recordSuccess(db, "osv:Ubuntu", now, SyncResult{}, now))
	inv := &Inventory{DB: db, now: clock.now}
	require.NoError(t, inv.ingestSnapshot("N1", 1, CategoryOS, []byte(`[{"platform":"debian","version":"12 (bookworm)","major":"12"}]`)))
	require.NoError(t, inv.ingestSnapshot("N2", 1, CategoryOS, []byte(`[{"platform":"ubuntu","version":"22.04.4 LTS","major":"22"}]`)))
	w := newTestWorker(t, db, srv.URL, clock)
	w.cfg.Ecosystems = []string{"Debian"} // narrowed while N2 still runs Ubuntu
	require.NoError(t, db.Create(&[]nodes.OsqueryNode{{UUID: "N1"}, {UUID: "N2"}}).Error)
	clock.advance(time.Second)
	require.NoError(t, w.Tick(context.Background()))
	var n int64
	require.NoError(t, db.Model(&SyncState{}).Where("source = ?", "osv:Ubuntu").Count(&n).Error)
	assert.Equal(t, int64(1), n)

	t.Run("empty fleet", func(t *testing.T) {
		empty := newTestDB(t) // a subtest's own database
		require.NoError(t, recordSuccess(empty, "osv:Debian", now, SyncResult{}, now))
		we := newTestWorker(t, empty, srv.URL, clock)
		require.NoError(t, we.Tick(context.Background()))
		var n int64
		require.NoError(t, empty.Model(&SyncState{}).Where("source = ?", "osv:Debian").Count(&n).Error)
		assert.Equal(t, int64(1), n, "an empty fleet drops nothing")
	})
}
