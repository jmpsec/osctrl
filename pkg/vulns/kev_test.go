package vulns

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKEVFlagsAdvisoriesThroughAliasesAndFindings(t *testing.T) {
	fs, srv := newFeedServer(t)
	db := newTestDB(t)
	clock := newClock()
	require.NoError(t, db.Create(&Advisory{ID: "DSA-1-1", Severity: SeverityHigh}).Error)
	require.NoError(t, db.Create(&Alias{AdvisoryID: "DSA-1-1", Alias: "CVE-2026-0001"}).Error)
	require.NoError(t, db.Create(&Advisory{ID: "DSA-2-1", Severity: SeverityLow}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "N", AdvisoryID: "DSA-1-1", Ecosystem: "Debian:12", Package: "openssl", Severity: SeverityUnknown}).Error)
	f := fetcher{client: http.DefaultClient, maxBytes: 1 << 20}

	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2026-0001"}, {"cveID": "CVE-2020-9999"}]}`))
	require.NoError(t, syncKEV(context.Background(), db, f, srv.URL+"/kev.json", clock.now()))

	var a1, a2 Advisory
	require.NoError(t, db.First(&a1, "id = ?", "DSA-1-1").Error)
	require.NoError(t, db.First(&a2, "id = ?", "DSA-2-1").Error)
	assert.True(t, a1.KEV)
	assert.False(t, a2.KEV)
	var finding Finding
	require.NoError(t, db.First(&finding).Error)
	assert.True(t, finding.KEV, "findings pick up KEV without re-matching")
	assert.Equal(t, SeverityHigh, finding.Severity, "and the advisory's current severity")

	fs.set("/kev.json", []byte(`{"vulnerabilities": [{"cveID": "CVE-2020-9999"}]}`))
	require.NoError(t, syncKEV(context.Background(), db, f, srv.URL+"/kev.json", clock.now()))
	require.NoError(t, db.First(&a1, "id = ?", "DSA-1-1").Error)
	assert.False(t, a1.KEV, "removal from the catalog clears the flag")
}

// A truncated or wrong file must not silently clear every KEV flag.
func TestKEVRejectsAnEmptyCatalog(t *testing.T) {
	fs, srv := newFeedServer(t)
	db := newTestDB(t)
	require.NoError(t, db.Create(&KEV{CVEID: "CVE-2026-0001"}).Error)
	fs.set("/kev.json", []byte(`{"vulnerabilities": []}`))
	err := syncKEV(context.Background(), db, fetcher{client: http.DefaultClient, maxBytes: 1 << 20}, srv.URL+"/kev.json", newClock().now())
	require.Error(t, err)
	var n int64
	db.Model(&KEV{}).Count(&n)
	assert.Equal(t, int64(1), n)
}
