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
