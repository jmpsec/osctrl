package vulns

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingsAfterListsOpenConfirmedFindingsWithHostnames(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "N1", Hostname: "web-01"}).Error)
	resolved := time.Now()
	rows := []Finding{
		{NodeUUID: "N1", EnvironmentID: 1, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.13-1", Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed},
		{NodeUUID: "N1", EnvironmentID: 1, AdvisoryID: "CPE-1", Ecosystem: "cpe", Package: "acme:app", Severity: SeverityHigh, Confidence: ConfidencePossible},
		{NodeUUID: "N1", EnvironmentID: 1, AdvisoryID: "DSA-2", Ecosystem: "Debian:12", Package: "curl", Severity: SeverityHigh, Confidence: ConfidenceConfirmed, ResolvedAt: &resolved},
		{NodeUUID: "GONE", EnvironmentID: 1, AdvisoryID: "DSA-3", Ecosystem: "Debian:12", Package: "bash", Severity: SeverityLow, Confidence: ConfidenceConfirmed},
	}
	require.NoError(t, db.Create(&rows).Error)
	inv := &Inventory{DB: db, now: time.Now}

	got, err := inv.FindingsAfter(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Len(t, got, 2, "possible and resolved findings never alert")
	assert.Equal(t, "DSA-1", got[0].AdvisoryID)
	assert.Equal(t, "web-01", got[0].Hostname)
	assert.True(t, got[0].KEV)
	assert.Equal(t, "3.0.13-1", got[0].FixedVersion)
	assert.Equal(t, "DSA-3", got[1].AdvisoryID)
	assert.Empty(t, got[1].Hostname, "a deleted node has no hostname")

	after, err := inv.FindingsAfter(context.Background(), got[0].ID, 10)
	require.NoError(t, err)
	require.Len(t, after, 1)
	assert.Equal(t, "DSA-3", after[0].AdvisoryID)

	limited, err := inv.FindingsAfter(context.Background(), 0, 1)
	require.NoError(t, err)
	assert.Len(t, limited, 1)

	latest, err := inv.LatestFindingID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rows[3].ID, latest)
}

func TestLatestFindingIDIsZeroWithoutFindings(t *testing.T) {
	inv := &Inventory{DB: newTestDB(t), now: time.Now}
	latest, err := inv.LatestFindingID(context.Background())
	require.NoError(t, err)
	assert.Zero(t, latest)
}

// A finding that becomes known-exploited, or more severe, while open is news
// again: refreshFlags records it once, before findings take the new values.
func TestRefreshFlagsRecordsEscalations(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	resolved := now
	require.NoError(t, db.Create(&[]Advisory{
		{ID: "DSA-1", Source: AdvisorySourceOSV, Severity: SeverityHigh},
		{ID: "DSA-2", Source: AdvisorySourceOSV, Severity: SeverityCritical},
		{ID: "DSA-3", Source: AdvisorySourceOSV, Severity: SeverityLow},
	}).Error)
	require.NoError(t, db.Create(&Alias{AdvisoryID: "DSA-1", Alias: "CVE-2026-1"}).Error)
	require.NoError(t, db.Create(&KEV{CVEID: "CVE-2026-1"}).Error)
	require.NoError(t, db.Create(&[]Finding{
		{NodeUUID: "N1", AdvisoryID: "DSA-1", Ecosystem: "e", Package: "p1", Severity: SeverityHigh, Confidence: ConfidenceConfirmed},   // becomes KEV
		{NodeUUID: "N1", AdvisoryID: "DSA-2", Ecosystem: "e", Package: "p2", Severity: SeverityMedium, Confidence: ConfidenceConfirmed}, // rises
		{NodeUUID: "N1", AdvisoryID: "DSA-3", Ecosystem: "e", Package: "p3", Severity: SeverityHigh, Confidence: ConfidenceConfirmed},   // falls: not news
		{NodeUUID: "N2", AdvisoryID: "DSA-2", Ecosystem: "e", Package: "p2", Severity: SeverityMedium, Confidence: ConfidenceConfirmed, ResolvedAt: &resolved},
		{NodeUUID: "N3", AdvisoryID: "DSA-2", Ecosystem: cpeEcosystem, Package: "x:y", Severity: SeverityMedium, Confidence: ConfidencePossible},
	}).Error)

	require.NoError(t, refreshFlags(db, now))
	var got []Escalation
	require.NoError(t, db.Order("finding_id").Find(&got).Error)
	require.Len(t, got, 2, "resolved, possible and less severe findings are not escalations")
	assert.Equal(t, uint(1), got[0].FindingID)
	assert.False(t, got[0].PrevKEV)
	assert.Equal(t, SeverityHigh, got[0].PrevSeverity)
	assert.Equal(t, uint(2), got[1].FindingID)
	assert.Equal(t, SeverityMedium, got[1].PrevSeverity)

	require.NoError(t, refreshFlags(db, now))
	var n int64
	require.NoError(t, db.Model(&Escalation{}).Count(&n).Error)
	assert.Equal(t, int64(2), n, "recorded once")
}

func TestEscalationsAfterListsOpenConfirmedFindings(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "N1", Hostname: "web-01"}).Error)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	resolved := now
	open := Finding{NodeUUID: "N1", EnvironmentID: 1, AdvisoryID: "DSA-1", Ecosystem: "e", Package: "openssl",
		Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed, FirstSeen: now.Add(-time.Hour)}
	gone := Finding{NodeUUID: "N1", EnvironmentID: 1, AdvisoryID: "DSA-2", Ecosystem: "e", Package: "curl",
		Severity: SeverityHigh, Confidence: ConfidenceConfirmed, ResolvedAt: &resolved}
	require.NoError(t, db.Create(&open).Error)
	require.NoError(t, db.Create(&gone).Error)
	require.NoError(t, db.Create(&[]Escalation{
		{FindingID: open.ID, PrevSeverity: SeverityHigh, CreatedAt: now},
		{FindingID: gone.ID, PrevSeverity: SeverityMedium, CreatedAt: now},
	}).Error)
	inv := &Inventory{DB: db, now: time.Now}

	got, err := inv.EscalationsAfter(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Len(t, got, 1, "an escalation of a resolved finding is no longer news")
	assert.Equal(t, uint(1), got[0].ID, "the escalation's id")
	assert.True(t, got[0].Escalated)
	assert.Equal(t, SeverityHigh, got[0].PrevSeverity)
	assert.True(t, got[0].KEV)
	assert.Equal(t, "web-01", got[0].Hostname)
	latest, err := inv.LatestEscalationID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(2), latest)
}
