package vulns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedFindings(t *testing.T, r *Reader, now time.Time) {
	t.Helper()
	resolved := now.Add(-time.Hour)
	rows := []Finding{
		{NodeUUID: "A1", EnvironmentID: 1, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed},
		{NodeUUID: "A2", EnvironmentID: 1, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed},
		{NodeUUID: "A1", EnvironmentID: 1, AdvisoryID: "DSA-2", Ecosystem: "Debian:12", Package: "curl", Severity: SeverityMedium, Confidence: ConfidenceConfirmed},
		{NodeUUID: "A1", EnvironmentID: 1, AdvisoryID: "DSA-3", Ecosystem: "Debian:12", Package: "bash", Severity: SeverityHigh, Confidence: ConfidenceConfirmed, ResolvedAt: &resolved},
		{NodeUUID: "B1", EnvironmentID: 2, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed},
	}
	require.NoError(t, r.DB.Create(&rows).Error)
	require.NoError(t, r.DB.Create(&NodeState{NodeUUID: "A1", EnvironmentID: 1, NotAssessed: 3}).Error)
	require.NoError(t, r.DB.Create(&NodeState{NodeUUID: "A2", EnvironmentID: 1, NotAssessed: 2}).Error)
	require.NoError(t, r.DB.Create(&Advisory{ID: "DSA-1", Severity: SeverityCritical, RefURLs: `["https://example.org/DSA-1"]`}).Error)
	require.NoError(t, r.DB.Create(&Alias{AdvisoryID: "DSA-1", Alias: "CVE-2026-0001"}).Error)
}

func newTestReader(t *testing.T) (*Reader, *fixedClock) {
	clock := newClock()
	r := NewReader(newTestDB(t), 6*time.Hour)
	r.now = clock.now
	return r, clock
}

func TestFindingsAreScopedAndFiltered(t *testing.T) {
	r, clock := newTestReader(t)
	seedFindings(t, r, clock.now())

	open, total, err := r.Findings(FindingFilter{EnvironmentID: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total, "open findings only, environment 1 only")
	assert.Len(t, open, 3)

	kev, _, err := r.Findings(FindingFilter{EnvironmentID: 1, KEV: true})
	require.NoError(t, err)
	assert.Len(t, kev, 2)

	resolved, _, err := r.Findings(FindingFilter{EnvironmentID: 1, State: StateResolved})
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "DSA-3", resolved[0].AdvisoryID)

	page, total, err := r.Findings(FindingFilter{EnvironmentID: 1, Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, page, 1)

	_, _, err = r.Findings(FindingFilter{EnvironmentID: 1, Severity: "catastrophic"})
	assert.ErrorIs(t, err, ErrBadFilter)
}

func TestSummary(t *testing.T) {
	r, clock := newTestReader(t)
	seedFindings(t, r, clock.now())
	s, err := r.Summary(1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), s.BySeverity[SeverityCritical][ConfidenceConfirmed])
	assert.Equal(t, int64(1), s.BySeverity[SeverityMedium][ConfidenceConfirmed])
	assert.Equal(t, int64(2), s.KEV)
	assert.Equal(t, int64(2), s.AffectedNodes)
	assert.Equal(t, int64(5), s.NotAssessed)
	require.NotEmpty(t, s.TopAdvisories)
	assert.Equal(t, CountRow{Name: "DSA-1", Total: 2}, s.TopAdvisories[0])
	assert.False(t, s.Loaded, "no feed has synced yet")
}

func TestAdvisoryDetailListsOnlyTheRequestedEnvironment(t *testing.T) {
	r, clock := newTestReader(t)
	seedFindings(t, r, clock.now())
	d, err := r.Advisory("DSA-1", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2026-0001"}, d.Aliases)
	assert.Equal(t, []string{"https://example.org/DSA-1"}, d.References)
	require.Len(t, d.Findings, 2)
	for _, f := range d.Findings {
		assert.Equal(t, uint(1), f.EnvironmentID)
	}
}

func TestFeedFreshness(t *testing.T) {
	r, clock := newTestReader(t)
	now := clock.now()
	require.NoError(t, recordSuccess(r.DB, "osv:Debian", now, SyncResult{}, now))
	require.NoError(t, recordSuccess(r.DB, sourceKEV, now, SyncResult{}, now))
	s, err := r.Summary(1)
	require.NoError(t, err)
	assert.True(t, s.Loaded)
	assert.False(t, s.Stale)

	clock.advance(18*time.Hour + time.Second)
	s, err = r.Summary(1)
	require.NoError(t, err)
	assert.True(t, s.Stale, "older than three sync intervals")
}

func TestSummaryCountsPossibleFindingsApart(t *testing.T) {
	r, clock := newTestReader(t)
	seedFindings(t, r, clock.now())
	require.NoError(t, r.DB.Create(&Finding{NodeUUID: "C1", EnvironmentID: 1, AdvisoryID: "CVE-2026-9", Ecosystem: cpeEcosystem,
		Package: "mozilla:firefox", Severity: SeverityCritical, KEV: true, Confidence: ConfidencePossible}).Error)
	s, err := r.Summary(1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), s.Possible)
	assert.Equal(t, int64(1), s.BySeverity[SeverityCritical][ConfidencePossible])
	assert.Equal(t, int64(2), s.KEV, "headline counts are confirmed only")
	assert.Equal(t, int64(2), s.AffectedNodes)
	for _, row := range s.TopAdvisories {
		assert.NotEqual(t, "CVE-2026-9", row.Name)
	}
	for _, row := range s.TopPackages {
		assert.NotEqual(t, "mozilla:firefox", row.Name)
	}
}

func TestAdvisoryAliasesLeaveOutTheIDItself(t *testing.T) {
	r, _ := newTestReader(t)
	require.NoError(t, r.DB.Create(&Advisory{ID: "CVE-2026-9", Source: AdvisorySourceNVD, Severity: SeverityHigh, RefURLs: "[]"}).Error)
	require.NoError(t, r.DB.Create(&[]Alias{
		{AdvisoryID: "CVE-2026-9", Alias: "CVE-2026-9"}, {AdvisoryID: "CVE-2026-9", Alias: "GHSA-aaaa-bbbb-cccc"},
	}).Error)
	d, err := r.Advisory("CVE-2026-9", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, d.Aliases)
}
