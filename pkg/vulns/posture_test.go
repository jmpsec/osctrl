package vulns

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGradeVulnerabilities(t *testing.T) {
	row := func(r map[string]any) map[string][]map[string]interface{} {
		return map[string][]map[string]interface{}{EvidenceCategory: {r}}
	}
	tests := []struct {
		name     string
		counts   map[string]any
		status   string
		severity posture.Severity
	}{
		{"kev fails critical", map[string]any{"kev": 1.0, "low": 1.0}, "fail", posture.SeverityCritical},
		{"critical fails critical", map[string]any{"critical": 2.0}, "fail", posture.SeverityCritical},
		{"high fails high", map[string]any{"high": 1.0, "medium": 3.0}, "fail", posture.SeverityHigh},
		{"medium warns", map[string]any{"medium": 1.0}, "warn", posture.SeverityMedium},
		{"unknown only warns", map[string]any{"unknown": 4.0}, "warn", posture.SeverityMedium},
		{"no findings passes", map[string]any{}, "pass", posture.SeverityCritical},
		// Not assessed is never clean.
		{"no findings with unassessed packages warns", map[string]any{"not_assessed": 2.0}, "warn", posture.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, severity := gradeVulnerabilities(row(tt.counts))
			assert.Equal(t, tt.status, status)
			assert.Equal(t, tt.severity, severity)
		})
	}
}

func evidenceReader(t *testing.T) *Reader {
	t.Helper()
	r := NewReader(newTestDB(t), 6*time.Hour)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	return r
}

func markLoaded(t *testing.T, r *Reader) {
	t.Helper()
	now := r.now()
	require.NoError(t, recordSuccess(r.DB, "osv:Debian", now, SyncResult{}, now))
}

// Before advisory data loads, nothing is evidence: a matched node with no
// findings must not pass the control.
func TestScoreEvidenceNeedsLoadedAdvisoryData(t *testing.T) {
	r := evidenceReader(t)
	matched := r.now()
	// Matched with an assessed package: only the missing advisory data
	// keeps it out.
	require.NoError(t, r.DB.Create(&NodeState{NodeUUID: "N1", InventoryAt: matched, MatchedAt: &matched, Assessed: 1}).Error)
	require.NoError(t, r.DB.Create(&NodeSoftware{NodeUUID: "N1", Category: CategoryDeb, Name: "bash", Version: "5.2-1"}).Error)
	out, err := r.ScoreEvidence([]string{"N1"})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestScoreEvidenceCountsOpenConfirmedFindings(t *testing.T) {
	r := evidenceReader(t)
	markLoaded(t, r)
	matched := r.now()
	resolved := r.now()
	require.NoError(t, r.DB.Create(&[]NodeState{
		{NodeUUID: "CLEAN", InventoryAt: matched, MatchedAt: &matched, Assessed: 1},
		{NodeUUID: "PENDING", InventoryAt: matched},
		// Nothing assessable (Amazon Linux, or an OS-only Windows node).
		{NodeUUID: "AMZN", InventoryAt: matched, MatchedAt: &matched, NotAssessed: 2},
		{NodeUUID: "BARE", InventoryAt: matched, MatchedAt: &matched},
		{NodeUUID: "PARTIAL", InventoryAt: matched, MatchedAt: &matched, NotAssessed: 1, Assessed: 1},
	}).Error)
	require.NoError(t, r.DB.Create(&[]NodeSoftware{
		{NodeUUID: "CLEAN", Category: CategoryDeb, Name: "bash", Version: "5.2-1"},
		{NodeUUID: "AMZN", Category: CategoryRPM, Name: "bash", Version: "5.2-1"},
		{NodeUUID: "AMZN", Category: CategoryRPM, Name: "curl", Version: "8.5-1"},
		{NodeUUID: "PARTIAL", Category: CategoryDeb, Name: "bash", Version: "5.2-1"},
		{NodeUUID: "PARTIAL", Category: CategoryPython, Name: "odd", Version: "dev"},
	}).Error)
	require.NoError(t, r.DB.Create(&[]Finding{
		{NodeUUID: "N1", AdvisoryID: "A1", Ecosystem: "e", Package: "p1", Severity: SeverityCritical, KEV: true, Confidence: ConfidenceConfirmed},
		{NodeUUID: "N1", AdvisoryID: "A2", Ecosystem: "e", Package: "p2", Severity: SeverityHigh, Confidence: ConfidenceConfirmed},
		{NodeUUID: "N1", AdvisoryID: "A3", Ecosystem: "e", Package: "p3", Severity: SeverityHigh, Confidence: ConfidencePossible},
		{NodeUUID: "N1", AdvisoryID: "A4", Ecosystem: "e", Package: "p4", Severity: SeverityLow, Confidence: ConfidenceConfirmed, ResolvedAt: &resolved},
	}).Error)

	out, err := r.ScoreEvidence([]string{"N1", "CLEAN", "PENDING", "UNKNOWN", "AMZN", "BARE", "PARTIAL"})
	require.NoError(t, err)
	// N1 has findings (it is evaluated even with matched_at cleared by a
	// sync); CLEAN and PARTIAL were matched with assessed packages; PENDING
	// and UNKNOWN never matched; AMZN and BARE have nothing assessed.
	require.Len(t, out, 3)
	require.Len(t, out["N1"], 1)
	assert.Equal(t, EvidenceCategory, out["N1"][0].Category)
	assert.JSONEq(t, `[{"critical":1,"high":1,"medium":0,"low":0,"unknown":0,"kev":1,"not_assessed":0}]`, out["N1"][0].Summary)
	assert.JSONEq(t, `[{"critical":0,"high":0,"medium":0,"low":0,"unknown":0,"kev":0,"not_assessed":0}]`, out["CLEAN"][0].Summary)
	assert.JSONEq(t, `[{"critical":0,"high":0,"medium":0,"low":0,"unknown":0,"kev":0,"not_assessed":1}]`, out["PARTIAL"][0].Summary)
}

// End to end through the posture manager: a KEV finding makes the node
// critical; a clean matched node passes the control.
func TestPostureScoresVulnerabilities(t *testing.T) {
	r := evidenceReader(t)
	markLoaded(t, r)
	matched := r.now()
	require.NoError(t, r.DB.Create(&[]NodeState{
		{NodeUUID: "N1", InventoryAt: matched, MatchedAt: &matched},
		{NodeUUID: "CLEAN", InventoryAt: matched, MatchedAt: &matched, Assessed: 1},
	}).Error)
	require.NoError(t, r.DB.Create(&Finding{NodeUUID: "N1", AdvisoryID: "A1", Ecosystem: "e", Package: "p1",
		Severity: SeverityMedium, KEV: true, Confidence: ConfidenceConfirmed}).Error)
	require.NoError(t, r.DB.Create(&NodeSoftware{NodeUUID: "CLEAN", Category: CategoryDeb, Name: "bash", Version: "5.2-1"}).Error)
	pm := posture.NewPostureManager(r.DB)
	pm.Evidence = r

	bad, err := pm.ScoreNode("N1")
	require.NoError(t, err)
	require.Len(t, bad.Controls, 1)
	assert.Equal(t, "fail", bad.Controls[0].Status)
	assert.Equal(t, "critical", bad.RiskLevel)

	clean, err := pm.ScoreNode("CLEAN")
	require.NoError(t, err)
	require.Len(t, clean.Controls, 1)
	assert.Equal(t, "pass", clean.Controls[0].Status)
}

// A name-based NVD match is a hint: CPE-only packages neither pass nor warn
// the control, and possible findings are not findings for scoring.
func TestScoreEvidenceIgnoresCPEPackages(t *testing.T) {
	r := evidenceReader(t)
	markLoaded(t, r)
	matched := r.now()
	require.NoError(t, r.DB.Create(&[]NodeState{
		{NodeUUID: "WIN", InventoryAt: matched, MatchedAt: &matched},
		{NodeUUID: "MAC", InventoryAt: matched, MatchedAt: &matched, NotAssessed: 2, Assessed: 1},
	}).Error)
	require.NoError(t, r.DB.Create(&[]NodeSoftware{
		{NodeUUID: "WIN", Category: CategoryPrograms, Name: "Mozilla Firefox", Version: "128.0.3"},
		{NodeUUID: "WIN", Category: CategoryPrograms, Name: "7-Zip", Version: "23.01"},
		{NodeUUID: "MAC", Category: CategoryPython, Name: "requests", Version: "2.31.0"},
		{NodeUUID: "MAC", Category: CategoryApps, Name: "Firefox", Version: "128.0.3"},
		{NodeUUID: "MAC", Category: CategoryApps, Name: "Slack", Version: "4.0"},
	}).Error)
	require.NoError(t, r.DB.Create(&Finding{NodeUUID: "WIN", AdvisoryID: "CVE-2026-1000", Ecosystem: cpeEcosystem,
		Package: "mozilla:firefox", Severity: SeverityCritical, Confidence: ConfidencePossible}).Error)

	out, err := r.ScoreEvidence([]string{"WIN", "MAC"})
	require.NoError(t, err)
	assert.NotContains(t, out, "WIN", "a node assessed only through CPE is unevaluated")
	require.Contains(t, out, "MAC")
	assert.JSONEq(t, `[{"critical":0,"high":0,"medium":0,"low":0,"unknown":0,"kev":0,"not_assessed":0}]`, out["MAC"][0].Summary,
		"apps NVD could not assess do not make the Python inventory less clean")
}

// An advisory sync clears matched_at fleet-wide. A clean node keeps its last
// assessment instead of losing the control until it is re-matched.
func TestScoreEvidenceKeepsCleanNodesAcrossSyncs(t *testing.T) {
	r := evidenceReader(t)
	markLoaded(t, r)
	require.NoError(t, r.DB.Create(&NodeState{NodeUUID: "CLEAN", InventoryAt: r.now(), Assessed: 1}).Error)
	require.NoError(t, r.DB.Create(&NodeSoftware{NodeUUID: "CLEAN", Category: CategoryDeb, Name: "bash", Version: "5.2-1"}).Error)
	out, err := r.ScoreEvidence([]string{"CLEAN"})
	require.NoError(t, err)
	assert.Contains(t, out, "CLEAN")
}

// The worker stops re-matching nodes silent for 30 days, so new advisories
// never reach them: a clean result that old is no longer evidence.
func TestScoreEvidenceDropsNodesSilentForThirtyDays(t *testing.T) {
	r := evidenceReader(t)
	markLoaded(t, r)
	require.NoError(t, r.DB.Create(&NodeState{NodeUUID: "SILENT", InventoryAt: r.now().Add(-staleNodeAge - time.Hour), Assessed: 1}).Error)
	require.NoError(t, r.DB.Create(&NodeSoftware{NodeUUID: "SILENT", Category: CategoryDeb, Name: "bash", Version: "5.2-1"}).Error)
	out, err := r.ScoreEvidence([]string{"SILENT"})
	require.NoError(t, err)
	assert.NotContains(t, out, "SILENT")
}
