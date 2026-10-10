package vulns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const cvss75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

func advisoryByID(t *testing.T, db *gorm.DB, id string) Advisory {
	t.Helper()
	var a Advisory
	require.NoError(t, db.First(&a, "id = ?", id).Error)
	return a
}

// Debian and Ubuntu records often carry no CVSS. With NVD on they borrow the
// highest score of an aliased CVE, and lose it again when the CVE goes.
func TestRefreshFlagsBorrowsTheAliasedNVDScore(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, db.Create(&[]Advisory{
		{ID: "DSA-1", Source: AdvisorySourceOSV, Severity: SeverityUnknown},
		{ID: "DSA-2", Source: AdvisorySourceOSV, Severity: SeverityHigh, CVSSVector: cvss75, CVSSScore: 7.5},
		{ID: "CVE-1", Source: AdvisorySourceNVD, Severity: SeverityHigh, CVSSVector: cvss75, CVSSScore: 7.5},
		{ID: "CVE-2", Source: AdvisorySourceNVD, Severity: SeverityCritical, CVSSVector: cvss98, CVSSScore: 9.8},
	}).Error)
	require.NoError(t, db.Create(&[]Alias{
		{AdvisoryID: "DSA-1", Alias: "CVE-1"}, {AdvisoryID: "DSA-1", Alias: "CVE-2"}, {AdvisoryID: "DSA-2", Alias: "CVE-2"},
	}).Error)
	require.NoError(t, db.Create(&Finding{NodeUUID: "N1", AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl",
		Severity: SeverityUnknown, Confidence: ConfidenceConfirmed}).Error)

	require.NoError(t, refreshFlags(db, time.Now()))
	dsa1 := advisoryByID(t, db, "DSA-1")
	assert.Equal(t, SeverityCritical, dsa1.Severity, "the highest-scored alias wins")
	assert.Equal(t, "CVE-2", dsa1.CVSSFrom)
	assert.Equal(t, cvss98, dsa1.CVSSVector)
	dsa2 := advisoryByID(t, db, "DSA-2")
	assert.Equal(t, SeverityHigh, dsa2.Severity, "a record's own score is kept")
	assert.Empty(t, dsa2.CVSSFrom)
	var f Finding
	require.NoError(t, db.First(&f).Error)
	assert.Equal(t, SeverityCritical, f.Severity, "findings follow their advisory")

	// The CVE goes away (NVD turned off): the borrowed score goes with it.
	require.NoError(t, db.Where("source = ?", AdvisorySourceNVD).Delete(&Advisory{}).Error)
	require.NoError(t, refreshFlags(db, time.Now()))
	dsa1 = advisoryByID(t, db, "DSA-1")
	assert.Equal(t, SeverityUnknown, dsa1.Severity)
	assert.Empty(t, dsa1.CVSSFrom)
	assert.Empty(t, dsa1.CVSSVector)
	require.NoError(t, db.First(&f).Error)
	assert.Equal(t, SeverityUnknown, f.Severity)
}

// Re-importing an OSV record restores its own score; the borrowed one is
// recomputed on the next refresh.
func TestOSVReimportClearsTheBorrowedScore(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, db.Create(&Advisory{ID: "DSA-1-1", Source: AdvisorySourceOSV, Severity: SeverityCritical,
		CVSSVector: cvss98, CVSSScore: 9.8, CVSSFrom: "CVE-2"}).Error)
	p, err := parseOSV([]byte(debianRecord("DSA-1-1", "2026-10-02T00:00:00Z", "3.0.13-1")))
	require.NoError(t, err)
	require.NoError(t, storeAdvisory(db, p))
	a := advisoryByID(t, db, "DSA-1-1")
	assert.Empty(t, a.CVSSFrom)
	assert.Equal(t, SeverityUnknown, a.Severity)
}
