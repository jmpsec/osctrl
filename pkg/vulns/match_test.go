package vulns

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type matchFixture struct {
	db      *gorm.DB
	clock   *fixedClock
	matcher *Matcher
}

func newMatchFixture(t *testing.T) *matchFixture {
	db := newTestDB(t)
	clock := newClock()
	return &matchFixture{db: db, clock: clock, matcher: &Matcher{DB: db, now: clock.now}}
}

func (f *matchFixture) node(t *testing.T, uuid, platform, version, major string, sw ...NodeSoftware) {
	t.Helper()
	require.NoError(t, f.db.Create(&NodeState{NodeUUID: uuid, EnvironmentID: 1, OSPlatform: platform, OSVersion: version, OSMajor: major, InventoryAt: f.clock.now()}).Error)
	for i := range sw {
		sw[i].NodeUUID, sw[i].EnvironmentID = uuid, 1
	}
	if len(sw) > 0 {
		require.NoError(t, f.db.Create(&sw).Error)
	}
}

func (f *matchFixture) advisory(t *testing.T, id, severity, ecosystem, pkg string, ranges []Range) {
	t.Helper()
	raw, _ := json.Marshal(ranges)
	require.NoError(t, f.db.Create(&Advisory{ID: id, Severity: severity}).Error)
	require.NoError(t, f.db.Create(&Affected{AdvisoryID: id, Ecosystem: ecosystem, Package: pkg, Ranges: string(raw), Versions: "[]"}).Error)
}

func (f *matchFixture) findings(t *testing.T, uuid string) []Finding {
	t.Helper()
	var out []Finding
	require.NoError(t, f.db.Where("node_uuid = ?", uuid).Order("advisory_id").Find(&out).Error)
	return out
}

// Debian advisories are keyed by source package. Matching on the binary
// name alone would miss libssl3, and with it most of the Debian archive.
func TestMatchUsesTheSourcePackage(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12 (bookworm)", "12",
		NodeSoftware{Category: CategoryDeb, Name: "libssl3", SourceName: "openssl", Version: "3.0.11-1~deb12u1"})
	f.advisory(t, "DSA-5678-1", SeverityHigh, "Debian:12", "openssl", fixedAt("0", "3.0.13-1~deb12u1"))

	require.NoError(t, f.matcher.MatchNode("N1"))
	got := f.findings(t, "N1")
	require.Len(t, got, 1)
	assert.Equal(t, "openssl", got[0].Package)
	assert.Equal(t, "3.0.11-1~deb12u1", got[0].InstalledVersion)
	assert.Equal(t, "3.0.13-1~deb12u1", got[0].FixedVersion)
	assert.Equal(t, ConfidenceConfirmed, got[0].Confidence)
	assert.Equal(t, SeverityHigh, got[0].Severity)
	assert.Equal(t, uint(1), got[0].EnvironmentID)
}

func TestMatchTwoBinariesFromOneSourceAreOneFinding(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12",
		NodeSoftware{Category: CategoryDeb, Name: "libssl3", SourceName: "openssl", Version: "3.0.11-1"},
		NodeSoftware{Category: CategoryDeb, Name: "openssl", SourceName: "openssl", Version: "3.0.11-1"})
	f.advisory(t, "DSA-5678-1", SeverityHigh, "Debian:12", "openssl", fixedAt("0", "3.0.13-1"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	require.Len(t, f.findings(t, "N1"), 1)
}

func TestMatchIgnoresOtherReleasesAndPatchedVersions(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12",
		NodeSoftware{Category: CategoryDeb, Name: "curl", Version: "7.88.1-10+deb12u5"},
		NodeSoftware{Category: CategoryDeb, Name: "bash", Version: "5.2.15-2+b2"})
	f.advisory(t, "DSA-1-1", SeverityHigh, "Debian:11", "curl", fixedAt("0", "9.0"))
	f.advisory(t, "DSA-2-1", SeverityHigh, "Debian:12", "bash", fixedAt("0", "5.2.15-2+b2"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	assert.Empty(t, f.findings(t, "N1"))
}

func TestMatchPyPINamesAreNormalizedOnBothSides(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "darwin", "15.1", "15", NodeSoftware{Category: CategoryPython, Name: "Django", Version: "4.2.1"})
	f.advisory(t, "PYSEC-1", SeverityCritical, "PyPI", "django", fixedAt("4.0", "4.2.2"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	require.Len(t, f.findings(t, "N1"), 1)
}

func TestMatchRPMWithEpoch(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "rhel", "9.4 (Plow)", "9", NodeSoftware{Category: CategoryRPM, Name: "nodejs", Version: "1:22.23.1-1.module+el9.8.0+1+abc"})
	f.advisory(t, "RHSA-2026:76750", SeverityHigh, "Red Hat:9", "nodejs", fixedAt("0", "1:22.23.2-2.module+el9.8.0+24958+80b2ac6e"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	require.Len(t, f.findings(t, "N1"), 1)
}

func TestMatchCountsWhatItCannotAssess(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "centos", "7", "7",
		NodeSoftware{Category: CategoryRPM, Name: "openssl", Version: "1.0.2k-26.el7"}, // unknown distro
		NodeSoftware{Category: CategoryPython, Name: "weird", Version: "unknown"},      // no digit
		NodeSoftware{Category: CategoryPython, Name: "requests", Version: "2.31.0"})    // assessable
	require.NoError(t, f.matcher.MatchNode("N1"))
	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "N1").Error)
	assert.Equal(t, 2, state.NotAssessed)
	require.NotNil(t, state.MatchedAt)
}

func TestFindingsResolveAndReopenKeepingFirstSeen(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12", NodeSoftware{Category: CategoryDeb, Name: "openssl", Version: "3.0.11-1"})
	f.advisory(t, "DSA-1-1", SeverityHigh, "Debian:12", "openssl", fixedAt("0", "3.0.13-1"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	firstSeen := f.findings(t, "N1")[0].FirstSeen

	// Upgraded: resolved, not deleted.
	f.clock.advance(time.Hour)
	require.NoError(t, f.db.Model(&NodeSoftware{}).Where("node_uuid = ?", "N1").Update("version", "3.0.13-1").Error)
	require.NoError(t, f.matcher.MatchNode("N1"))
	got := f.findings(t, "N1")
	require.Len(t, got, 1)
	require.NotNil(t, got[0].ResolvedAt)
	assert.Equal(t, f.clock.now(), got[0].ResolvedAt.UTC())

	// Downgraded again: reopened with its original first_seen.
	f.clock.advance(time.Hour)
	require.NoError(t, f.db.Model(&NodeSoftware{}).Where("node_uuid = ?", "N1").Update("version", "3.0.11-1").Error)
	require.NoError(t, f.matcher.MatchNode("N1"))
	got = f.findings(t, "N1")
	require.Len(t, got, 1)
	assert.Nil(t, got[0].ResolvedAt)
	assert.Equal(t, firstSeen.UTC(), got[0].FirstSeen.UTC())
	assert.Equal(t, f.clock.now(), got[0].LastSeen.UTC())
}

// matched_at is the time the match started, so inventory written while a
// match runs is matched on the next pass instead of being skipped.
func TestMatchedAtIsTheStartTime(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12")
	start := f.clock.now()
	require.NoError(t, f.matcher.MatchNode("N1"))
	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "N1").Error)
	assert.Equal(t, start, state.MatchedAt.UTC())
}
