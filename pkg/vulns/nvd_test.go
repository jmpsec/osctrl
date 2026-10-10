package vulns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cvss98     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	firefoxCPE = "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"
)

// nvdEntry is one vulnerabilities[] entry shaped like the NVD CVE API 2.0.
// bounds goes inside the cpeMatch object: `, "versionEndExcluding": "130.0"`.
func nvdEntry(id, status, criteria, bounds string) string {
	return fmt.Sprintf(`{"cve": {"id": %q, "published": "2026-09-01T10:00:00.000", "lastModified": "2026-10-01T10:00:00.000",
	  "vulnStatus": %q, "descriptions": [{"lang": "en", "value": "Use after free in %s."}],
	  "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"vectorString": %q, "baseScore": 9.8}}]},
	  "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": %q%s}]}]}],
	  "references": [{"url": "https://example.org/%s"}]}}`, id, status, id, cvss98, criteria, bounds, id)
}

func nvdPageOf(total int, entries ...string) string {
	return fmt.Sprintf(`{"resultsPerPage": %d, "startIndex": 0, "totalResults": %d, "vulnerabilities": [%s]}`,
		len(entries), total, strings.Join(entries, ","))
}

// nvdServer serves pages by startIndex. failures are status codes returned,
// in order, before any page is served.
type nvdServer struct {
	mu       sync.Mutex
	pages    map[string]string
	failures []int
	queries  []url.Values
	keys     []string
}

func newNVDServer(t *testing.T) (*nvdServer, *httptest.Server) {
	ns := &nvdServer{pages: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns.mu.Lock()
		defer ns.mu.Unlock()
		ns.queries = append(ns.queries, r.URL.Query())
		ns.keys = append(ns.keys, r.Header.Get("apiKey"))
		if len(ns.failures) > 0 {
			code := ns.failures[0]
			ns.failures = ns.failures[1:]
			w.WriteHeader(code)
			return
		}
		body, ok := ns.pages[r.URL.Query().Get("startIndex")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return ns, srv
}

func (ns *nvdServer) set(startIndex, body string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.pages[startIndex] = body
}

func (ns *nvdServer) fail(codes ...int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.failures = append(ns.failures, codes...)
}

func newTestNVD(t *testing.T, baseURL, apiKey string, clock *fixedClock) (*NVDSource, *[]time.Duration) {
	t.Helper()
	s := newNVDSource(newTestDB(t), baseURL, apiKey, fetcher{client: http.DefaultClient, maxBytes: 10 << 20}, clock.now)
	var slept []time.Duration
	s.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	return s, &slept
}

func TestNVDFirstSyncStoresApplicationCVEs(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(3,
		nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`),
		nvdEntry("CVE-2026-1001", "Analyzed", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", `, "versionEndExcluding": "6.9"`)))
	ns.set("2", nvdPageOf(3, nvdEntry("CVE-2026-1002", "Analyzed", `cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6:*:*:*:*:*:*:*`, "")))
	s, slept := newTestNVD(t, srv.URL, "", newClock())

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, res.Written)

	var ids []string
	require.NoError(t, s.db.Model(&Advisory{}).Order("id").Pluck("id", &ids).Error)
	assert.Equal(t, []string{"CVE-2026-1000", "CVE-2026-1002"}, ids, "a CVE without application CPEs is not stored")

	var firefox Advisory
	require.NoError(t, s.db.First(&firefox, "id = ?", "CVE-2026-1000").Error)
	assert.Equal(t, AdvisorySourceNVD, firefox.Source)
	assert.Equal(t, SeverityCritical, firefox.Severity)
	assert.InDelta(t, 9.8, firefox.CVSSScore, 0.01)

	var affected []Affected
	require.NoError(t, s.db.Order("package").Find(&affected).Error)
	require.Len(t, affected, 2)
	assert.Equal(t, cpeEcosystem, affected[0].Ecosystem)
	assert.Equal(t, "mozilla:firefox", affected[0].Package)
	assert.JSONEq(t, `[{"end_excluding": "130.0"}]`, affected[0].Ranges)
	assert.Equal(t, "notepad-plus-plus:notepad++", affected[1].Package)
	assert.JSONEq(t, `["8.6"]`, affected[1].Versions)

	var products []CPEProduct
	require.NoError(t, s.db.Order("vendor").Find(&products).Error)
	assert.Equal(t, []CPEProduct{{Vendor: "mozilla", Product: "firefox"}, {Vendor: "notepad-plus-plus", Product: "notepad++"}}, products)

	var self int64
	require.NoError(t, s.db.Model(&Alias{}).Where("advisory_id = ? AND alias = ?", "CVE-2026-1000", "CVE-2026-1000").Count(&self).Error)
	assert.Equal(t, int64(1), self, "the CVE is its own alias, so the KEV refresh flags it")

	require.Len(t, ns.queries, 2)
	assert.Empty(t, ns.queries[0].Get("lastModStartDate"), "the first sync reads everything")
	assert.Equal(t, "2000", ns.queries[0].Get("resultsPerPage"))
	assert.Equal(t, "2", ns.queries[1].Get("startIndex"))
	assert.Equal(t, []time.Duration{6 * time.Second}, *slept, "unkeyed requests are paced 6 s apart")
}

func TestNVDIncrementalReadsTheModifiedWindow(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	clock := newClock()
	s, _ := newTestNVD(t, srv.URL, "test-key", clock)
	_, err := s.Sync(context.Background())
	require.NoError(t, err)
	firstStart := clock.now()

	clock.advance(6 * time.Hour)
	_, err = s.Sync(context.Background())
	require.NoError(t, err)
	// The window reaches back past the cursor: NVD indexes some records
	// after their lastModified time, and re-reading them is harmless.
	assert.Equal(t, firstStart.Add(-nvdOverlap).UTC().Format(nvdQueryTime), ns.queries[1].Get("lastModStartDate"))
	assert.Equal(t, clock.now().UTC().Format(nvdQueryTime), ns.queries[1].Get("lastModEndDate"))

	// Past the API's 120-day window the sync starts over.
	clock.advance(121 * 24 * time.Hour)
	_, err = s.Sync(context.Background())
	require.NoError(t, err)
	assert.Empty(t, ns.queries[2].Get("lastModStartDate"))

	assert.Equal(t, []string{"test-key", "test-key", "test-key"}, ns.keys, "the key travels as the apiKey header")
	for _, q := range ns.queries {
		assert.NotContains(t, q.Encode(), "test-key", "never in the URL")
	}
}

func TestNVDRetriesRateLimitedPages(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.fail(http.StatusForbidden, http.StatusServiceUnavailable)
	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	s, slept := newTestNVD(t, srv.URL, "", newClock())
	_, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []time.Duration{nvdRetryWait, nvdRetryWait}, *slept)
	assert.Len(t, ns.queries, 3)
}

func TestNVDFailedSyncKeepsDataAndCursor(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	clock := newClock()
	s, _ := newTestNVD(t, srv.URL, "test-key", clock)
	_, err := s.Sync(context.Background())
	require.NoError(t, err)
	var before SyncState
	require.NoError(t, s.db.First(&before, "source = ?", sourceNVD).Error)

	ns.fail(http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable)
	clock.advance(6 * time.Hour)
	_, err = s.Sync(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "test-key")

	var after SyncState
	require.NoError(t, s.db.First(&after, "source = ?", sourceNVD).Error)
	assert.Equal(t, before.Cursor.UTC(), after.Cursor.UTC(), "the cursor only moves after a complete sync")
	assert.NotEmpty(t, after.LastError)
	assert.NotContains(t, after.LastError, "test-key")
	var n int64
	require.NoError(t, s.db.Model(&Affected{}).Count(&n).Error)
	assert.Equal(t, int64(1), n, "stored CVEs survive a failed sync")
}

func TestNVDRejectedCVEIsRemoved(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	clock := newClock()
	s, _ := newTestNVD(t, srv.URL, "", clock)
	_, err := s.Sync(context.Background())
	require.NoError(t, err)

	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Rejected", firefoxCPE, "")))
	clock.advance(6 * time.Hour)
	_, err = s.Sync(context.Background())
	require.NoError(t, err)
	var n int64
	require.NoError(t, s.db.Model(&Advisory{}).Count(&n).Error)
	assert.Zero(t, n)
	require.NoError(t, s.db.Model(&Affected{}).Count(&n).Error)
	assert.Zero(t, n)
}

// A CVE id an OSV record already uses stays the OSV record's.
func TestNVDLeavesOSVRecordsAlone(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	s, _ := newTestNVD(t, srv.URL, "", newClock())
	require.NoError(t, s.db.Create(&Advisory{ID: "CVE-2026-1000", Source: AdvisorySourceOSV, Summary: "from OSV", Severity: SeverityHigh}).Error)
	require.NoError(t, s.db.Create(&Affected{AdvisoryID: "CVE-2026-1000", Ecosystem: "PyPI", Package: "requests", Ranges: "[]", Versions: "[]"}).Error)

	_, err := s.Sync(context.Background())
	require.NoError(t, err)
	var a Advisory
	require.NoError(t, s.db.First(&a, "id = ?", "CVE-2026-1000").Error)
	assert.Equal(t, "from OSV", a.Summary)
	assert.Equal(t, AdvisorySourceOSV, a.Source)
	var affected []Affected
	require.NoError(t, s.db.Find(&affected).Error)
	require.Len(t, affected, 1)
	assert.Equal(t, "PyPI", affected[0].Ecosystem)
}

func TestParseNVDGroupsVulnerableApplicationCPEs(t *testing.T) {
	c := nvdCVE{ID: "CVE-2026-2000", VulnStatus: "Analyzed", Configurations: []nvdConfiguration{{Nodes: []nvdNode{{CPEMatch: []nvdCPEMatch{
		{Vulnerable: true, Criteria: firefoxCPE, VersionStartIncluding: "100.0", VersionEndExcluding: "115.2"},
		{Vulnerable: true, Criteria: firefoxCPE, VersionStartIncluding: "120.0", VersionEndExcluding: "128.1"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:mozilla:firefox_esr:115.1:*:*:*:*:*:*:*"},
		{Vulnerable: false, Criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*"},
	}}}}}}
	p, products, err := parseNVD(c)
	require.NoError(t, err)
	require.Len(t, p.Affected, 2)
	assert.Equal(t, "mozilla:firefox", p.Affected[0].Package)
	assert.JSONEq(t, `[{"start_including":"100.0","end_excluding":"115.2"},{"start_including":"120.0","end_excluding":"128.1"}]`, p.Affected[0].Ranges)
	assert.Equal(t, "mozilla:firefox_esr", p.Affected[1].Package)
	assert.JSONEq(t, `["115.1"]`, p.Affected[1].Versions)
	assert.Len(t, products, 2, "the not-applicable (-) version and the platform CPE are dropped")
}

// A short or empty answer must not pass for a complete sync: the cursor would
// move past CVEs that were never read.
func TestNVDIncompleteAnswersFailTheSync(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(5000, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	ns.set("1", nvdPageOf(5000))
	s, _ := newTestNVD(t, srv.URL, "", newClock())
	_, err := s.Sync(context.Background())
	require.Error(t, err, "an empty page before totalResults is a truncated answer")
	var n int64
	require.NoError(t, s.db.Model(&SyncState{}).Where("source = ? AND last_success IS NOT NULL", sourceNVD).Count(&n).Error)
	assert.Zero(t, n)

	empty, emptySrv := newNVDServer(t)
	empty.set("0", `{}`)
	s2, _ := newTestNVD(t, emptySrv.URL, "", newClock())
	_, err = s2.Sync(context.Background())
	require.Error(t, err, "a full sync that lists nothing is a broken feed, not an empty one")
}

// A redirect to another host must not carry the API key along.
func TestNVDKeyDoesNotFollowCrossHostRedirects(t *testing.T) {
	other, otherSrv := newNVDServer(t)
	other.set("0", nvdPageOf(1, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+"/?"+r.URL.RawQuery, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	s, _ := newTestNVD(t, redirect.URL, "test-key", newClock())
	_, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{""}, other.keys)
}

// One record the database rejects is skipped and counted, not a sync that
// fails on every retry.
func TestNVDSkipsARecordTheDatabaseRejects(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(2,
		nvdEntry("CVE-2026-0666", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`),
		nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	s, _ := newTestNVD(t, srv.URL, "", newClock())
	require.NoError(t, s.db.Exec(`CREATE TRIGGER reject_bad BEFORE INSERT ON vuln_advisories
		WHEN NEW.id = 'CVE-2026-0666' BEGIN SELECT RAISE(ABORT, 'rejected'); END`).Error)
	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Written)
	assert.Equal(t, 1, res.Skipped)
	var ids []string
	require.NoError(t, s.db.Model(&Advisory{}).Pluck("id", &ids).Error)
	assert.Equal(t, []string{"CVE-2026-1000"}, ids)
}

func TestParseNVDSkipsKeysTooLongToStore(t *testing.T) {
	long := strings.Repeat("a", 128)
	c := nvdCVE{ID: "CVE-2026-2001", Configurations: []nvdConfiguration{{Nodes: []nvdNode{{CPEMatch: []nvdCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:" + long + ":" + long + ":1.0:*:*:*:*:*:*:*"},
	}}}}}}
	p, products, err := parseNVD(c)
	require.NoError(t, err)
	assert.Empty(t, p.Affected, "vendor:product must fit the 255-character package column")
	assert.Empty(t, products)
}

// A full sync that fails part-way continues from its next page, not page 0.
// NVD lists full results in a stable order and never deletes a CVE, and the
// first incremental sync covers anything modified since the full sync began.
func TestNVDResumesAFailedFullSync(t *testing.T) {
	ns, srv := newNVDServer(t)
	ns.set("0", nvdPageOf(2, nvdEntry("CVE-2026-1000", "Analyzed", firefoxCPE, `, "versionEndExcluding": "130.0"`)))
	clock := newClock()
	s, _ := newTestNVD(t, srv.URL, "", clock)
	firstStart := clock.now()
	_, err := s.Sync(context.Background())
	require.Error(t, err, "page 1 is missing")

	ns.set("1", nvdPageOf(2, nvdEntry("CVE-2026-1001", "Analyzed", firefoxCPE, `, "versionEndExcluding": "131.0"`)))
	clock.advance(time.Hour)
	_, err = s.Sync(context.Background())
	require.NoError(t, err)
	last := ns.queries[len(ns.queries)-1]
	assert.Equal(t, "1", last.Get("startIndex"), "resumes at the next page")
	assert.Empty(t, last.Get("lastModStartDate"))
	pageZero := 0
	for _, q := range ns.queries {
		if q.Get("startIndex") == "0" {
			pageZero++
		}
	}
	assert.Equal(t, 1, pageZero, "page 0 is not read again")

	var st SyncState
	require.NoError(t, s.db.First(&st, "source = ?", sourceNVD).Error)
	assert.Equal(t, firstStart, st.Cursor.UTC(), "the cursor is when the full sync began")
	assert.Nil(t, st.ResumeStart)
	var n int64
	require.NoError(t, s.db.Model(&Advisory{}).Count(&n).Error)
	assert.Equal(t, int64(2), n)
}
