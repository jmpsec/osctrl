package vulns

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func debianRecord(id, modified, fixed string) string {
	return fmt.Sprintf(`{"id": %q, "modified": %q, "upstream": ["CVE-%s"],
	  "affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": %q}]}]}]}`, id, modified, id, fixed)
}

func zipOf(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// feedServer serves an in-memory OSV bucket. files maps request paths, as
// the server sees them (decoded), to bodies; status overrides the code.
type feedServer struct {
	mu     sync.Mutex
	files  map[string][]byte
	status map[string]int
	hits   map[string]int
}

func newFeedServer(t *testing.T) (*feedServer, *httptest.Server) {
	fs := &feedServer{files: map[string][]byte{}, status: map[string]int{}, hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.hits[r.URL.Path]++
		if code, ok := fs.status[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		body, ok := fs.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return fs, srv
}

func (fs *feedServer) set(path string, body []byte) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.files[path] = body
	delete(fs.status, path)
}

func (fs *feedServer) fail(path string, code int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.status[path] = code
}

func (fs *feedServer) hitCount(path string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.hits[path]
}

func newTestOSV(t *testing.T, baseURL string, clock *fixedClock) *OSVSource {
	return &OSVSource{db: newTestDB(t), baseURL: baseURL, fetch: fetcher{client: http.DefaultClient, maxBytes: 10 << 20}, now: clock.now}
}

func advisoryIDs(t *testing.T, s *OSVSource) []string {
	var ids []string
	require.NoError(t, s.db.Model(&Advisory{}).Order("id").Pluck("id", &ids).Error)
	return ids
}

func TestOSVFirstSyncImportsTheArchive(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{
		"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1"),
		"DSA-2-1.json": debianRecord("DSA-2-1", "2026-10-03T00:00:00Z", "3.0.14-1"),
		"broken.json":  `{not json`,
		"README.txt":   "ignored",
		"../evil.json": debianRecord("DSA-3-1", "2026-10-02T00:00:00Z", "1.0-1"),
	}))
	clock := newClock()
	s := newTestOSV(t, srv.URL, clock)

	res, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)
	assert.Equal(t, 1, res.Skipped, "one malformed entry is skipped, not fatal")
	// Entries are parsed in memory: a "../" name is just a name.
	assert.Equal(t, []string{"DSA-1-1", "DSA-2-1", "DSA-3-1"}, advisoryIDs(t, s))
	_, statErr := os.Stat(filepath.Join(os.TempDir(), "..", "evil.json"))
	assert.True(t, os.IsNotExist(statErr))

	var st SyncState
	require.NoError(t, s.db.First(&st, "source = ?", "osv:Debian").Error)
	assert.Equal(t, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), st.Cursor.UTC(), "cursor is the newest modified time imported")
	require.NotNil(t, st.LastSuccess)
	assert.Equal(t, 1, st.LastSkipped)
}

func TestOSVIncrementalFetchesOnlyNewerRecords(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	s := newTestOSV(t, srv.URL, newClock())
	_, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)

	fs.set("/Debian/modified_id.csv", []byte(strings.Join([]string{
		"2026-10-05T10:42:30.33938859Z,DSA-4-1",
		"2026-10-04T00:00:00Z,DSA-1-1",
		"2026-10-01T00:00:00Z,DSA-0-1",
	}, "\n")))
	fs.set("/Debian/DSA-4-1.json", []byte(debianRecord("DSA-4-1", "2026-10-05T10:42:30.33938859Z", "3.0.15-1")))
	fs.set("/Debian/DSA-1-1.json", []byte(debianRecord("DSA-1-1", "2026-10-04T00:00:00Z", "3.0.16-1")))

	res, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)
	assert.Equal(t, 2, res.Written)
	assert.Zero(t, fs.hitCount("/Debian/DSA-0-1.json"), "records at or before the cursor are not fetched")
	assert.Equal(t, 1, fs.hitCount("/Debian/all.zip"), "the archive is only for the first sync")
	assert.Equal(t, []string{"DSA-1-1", "DSA-4-1"}, advisoryIDs(t, s))

	var aff Affected
	require.NoError(t, s.db.First(&aff, "advisory_id = ?", "DSA-1-1").Error)
	assert.Contains(t, aff.Ranges, "3.0.16-1", "an updated record replaces its affected rows")
}

func TestOSVWithdrawnRecordIsRemoved(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	s := newTestOSV(t, srv.URL, newClock())
	_, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)

	fs.set("/Debian/modified_id.csv", []byte("2026-10-05T00:00:00Z,DSA-1-1\n"))
	fs.set("/Debian/DSA-1-1.json", []byte(`{"id": "DSA-1-1", "modified": "2026-10-05T00:00:00Z", "withdrawn": "2026-10-05T00:00:00Z"}`))
	_, err = s.Sync(context.Background(), "Debian")
	require.NoError(t, err)
	assert.Empty(t, advisoryIDs(t, s))
	var n int64
	s.db.Model(&Affected{}).Count(&n)
	assert.Zero(t, n)
}

func TestOSVFailedSyncKeepsDataAndCursor(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	clock := newClock()
	s := newTestOSV(t, srv.URL, clock)
	_, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)

	fs.fail("/Debian/modified_id.csv", http.StatusInternalServerError)
	clock.advance(time.Hour)
	_, err = s.Sync(context.Background(), "Debian")
	require.Error(t, err)

	assert.Equal(t, []string{"DSA-1-1"}, advisoryIDs(t, s), "a failed sync deletes nothing")
	var st SyncState
	require.NoError(t, s.db.First(&st, "source = ?", "osv:Debian").Error)
	assert.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), st.Cursor.UTC())
	assert.Contains(t, st.LastError, "500")
	require.NotNil(t, st.LastErrorAt)
	assert.True(t, st.LastErrorAt.After(*st.LastSuccess))
}

func TestOSVMissingRecordIsSkippedNotFatal(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{"DSA-1-1.json": debianRecord("DSA-1-1", "2026-10-01T00:00:00Z", "3.0.13-1")}))
	s := newTestOSV(t, srv.URL, newClock())
	_, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)

	fs.set("/Debian/modified_id.csv", []byte("2026-10-05T00:00:00Z,DSA-9-1\n"))
	res, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err, "a record that vanished between listing and fetch must not wedge the cursor")
	assert.Equal(t, 1, res.Skipped)
}

func TestOSVDownloadCapIsEnforced(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", bytes.Repeat([]byte("x"), 2048))
	s := newTestOSV(t, srv.URL, newClock())
	s.fetch.maxBytes = 1024
	_, err := s.Sync(context.Background(), "Debian")
	require.ErrorIs(t, err, ErrTooLarge)
}

// A chunked response has no Content-Length, so the cap must also hold while
// reading the body.
func TestOSVDownloadCapHoldsWithoutContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for range 4 {
			_, _ = w.Write(bytes.Repeat([]byte("x"), 512))
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	f := fetcher{client: http.DefaultClient, maxBytes: 1024}
	_, err := f.readAll(context.Background(), srv.URL)
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestOSVEscapesEcosystemDirectories(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Red Hat/all.zip", zipOf(t, map[string]string{"RHSA-2026:76750.json": redHatRecord}))
	s := newTestOSV(t, srv.URL, newClock())
	_, err := s.Sync(context.Background(), "Red Hat")
	require.NoError(t, err)
	assert.Equal(t, []string{"RHSA-2026:76750"}, advisoryIDs(t, s))
}

func TestOSVSkipsARecordTheDatabaseRejects(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{
		"DSA-6-1.json": debianRecord("DSA-6-1", "2026-10-01T00:00:00Z", "3.0.13-1"),
		"DSA-7-1.json": debianRecord("DSA-7-1", "2026-10-01T00:00:00Z", "3.0.13-1"),
	}))
	s := newTestOSV(t, srv.URL, newClock())
	require.NoError(t, s.db.Exec(`CREATE TRIGGER reject_bad BEFORE INSERT ON vuln_advisories
		WHEN NEW.id = 'DSA-6-1' BEGIN SELECT RAISE(ABORT, 'rejected'); END`).Error)
	res, err := s.Sync(context.Background(), "Debian")
	require.NoError(t, err)
	assert.Equal(t, 1, res.Written)
	assert.Equal(t, 1, res.Skipped)
	assert.Equal(t, []string{"DSA-7-1"}, advisoryIDs(t, s))
}

// When every record fails the database is the problem, not the records: the
// sync fails (keeping its cursor) instead of reporting them all skipped.
func TestOSVFailsWhenTheDatabaseRejectsEverything(t *testing.T) {
	fs, srv := newFeedServer(t)
	fs.set("/Debian/all.zip", zipOf(t, map[string]string{
		"DSA-6-1.json": debianRecord("DSA-6-1", "2026-10-01T00:00:00Z", "3.0.13-1"),
		"DSA-7-1.json": debianRecord("DSA-7-1", "2026-10-01T00:00:00Z", "3.0.13-1"),
	}))
	s := newTestOSV(t, srv.URL, newClock())
	require.NoError(t, s.db.Exec(`CREATE TRIGGER reject_all BEFORE INSERT ON vuln_advisories
		BEGIN SELECT RAISE(ABORT, 'database unavailable'); END`).Error)
	_, err := s.Sync(context.Background(), "Debian")
	require.Error(t, err)
	var n int64
	require.NoError(t, s.db.Model(&SyncState{}).Where("source = ? AND last_success IS NOT NULL", "osv:Debian").Count(&n).Error)
	assert.Zero(t, n)
}
