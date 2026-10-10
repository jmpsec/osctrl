package vulns

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gather scrapes c through a pedantic registry, which also checks that
// Describe and Collect agree, keyed "name{label=value}".
func gather(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range m.GetLabel() {
				key += "{" + l.GetName() + "=" + l.GetValue() + "}"
			}
			out[key] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestMetricsReportFeedsFindingsAndQueue(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	now := clock.now()
	resolved := now
	require.NoError(t, recordSuccess(db, "osv:Debian", now, SyncResult{}, now))
	require.NoError(t, db.Create(&[]Advisory{{ID: "DSA-1", Severity: SeverityHigh}, {ID: "CVE-2026-1", Source: AdvisorySourceNVD, Severity: SeverityHigh}}).Error)
	require.NoError(t, db.Create(&[]Finding{
		{NodeUUID: "N1", AdvisoryID: "DSA-1", Ecosystem: "e", Package: "p1", Confidence: ConfidenceConfirmed},
		{NodeUUID: "N1", AdvisoryID: "CVE-2026-1", Ecosystem: cpeEcosystem, Package: "a:b", Confidence: ConfidencePossible},
		{NodeUUID: "N2", AdvisoryID: "DSA-1", Ecosystem: "e", Package: "p1", Confidence: ConfidenceConfirmed, ResolvedAt: &resolved},
	}).Error)
	require.NoError(t, db.Create(&[]NodeState{
		{NodeUUID: "N1", InventoryAt: now, MatchedAt: &now, NotAssessed: 3},
		{NodeUUID: "N2", InventoryAt: now, NotAssessed: 2},
	}).Error)
	c := newMetricsCollector(db, clock.now)

	assert.Equal(t, map[string]float64{
		"osctrl_vuln_advisories": 2,
		"osctrl_vuln_feed_last_success_timestamp_seconds{source=osv:Debian}": float64(now.Unix()),
		"osctrl_vuln_findings_open{confidence=confirmed}":                    1,
		"osctrl_vuln_findings_open{confidence=possible}":                     1,
		"osctrl_vuln_findings_resolved":                                      1,
		"osctrl_vuln_nodes_pending_match":                                    1,
		"osctrl_vuln_packages_not_assessed":                                  5,
	}, gather(t, c))

	// Scrapes within a minute reuse the last reading, so they cannot load
	// the database.
	require.NoError(t, db.Create(&Advisory{ID: "DSA-2", Severity: SeverityLow}).Error)
	assert.Equal(t, float64(2), gather(t, c)["osctrl_vuln_advisories"])
	clock.advance(metricsTTL)
	assert.Equal(t, float64(3), gather(t, c)["osctrl_vuln_advisories"])
}

// A read past its deadline fails rather than holding every scrape, and a
// failed read exports nothing: zeros would read as "no findings".
func TestMetricsFailClosed(t *testing.T) {
	db := newTestDB(t)
	clock := newClock()
	c := newMetricsCollector(db, clock.now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.query(ctx, clock.now())
	require.Error(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	assert.Empty(t, gather(t, c))
}
