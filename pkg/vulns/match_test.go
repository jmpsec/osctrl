package vulns

import (
	"encoding/json"
	"strings"
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
	dir, _, _ := strings.Cut(ecosystem, ":")
	f.synced(t, dir)
}

// synced records a successful sync of an OSV directory: advisories exist
// only once their feed has synced.
func (f *matchFixture) synced(t *testing.T, dir string) {
	t.Helper()
	now := f.clock.now()
	require.NoError(t, recordSuccess(f.db, osvSourcePrefix+dir, now, SyncResult{}, now))
}

// cpe adds an NVD CVE affecting vendor:product and records the NVD sync.
func (f *matchFixture) cpe(t *testing.T, id, severity, vendorProduct string, ranges []cpeRange, versions []string) {
	t.Helper()
	vendor, product, _ := strings.Cut(vendorProduct, ":")
	if ranges == nil {
		ranges = []cpeRange{}
	}
	if versions == nil {
		versions = []string{}
	}
	rawRanges, _ := json.Marshal(ranges)
	rawVersions, _ := json.Marshal(versions)
	require.NoError(t, f.db.Create(&Advisory{ID: id, Source: AdvisorySourceNVD, Severity: severity}).Error)
	require.NoError(t, f.db.Create(&Affected{AdvisoryID: id, Ecosystem: cpeEcosystem, Package: vendorProduct,
		Ranges: string(rawRanges), Versions: string(rawVersions)}).Error)
	require.NoError(t, f.db.FirstOrCreate(&CPEProduct{Vendor: vendor, Product: product}).Error)
	now := f.clock.now()
	require.NoError(t, recordSuccess(f.db, sourceNVD, now, SyncResult{}, now))
}

// windowsNode has three programs NVD lists, and one Python package for the
// confirmed path.
func (f *matchFixture) windowsNode(t *testing.T) {
	t.Helper()
	f.node(t, "W1", "windows", "10.0.22631", "10",
		NodeSoftware{Category: CategoryPrograms, Name: "Mozilla Firefox (x64 en-US)", Version: "128.0.3", Vendor: "Mozilla"},
		NodeSoftware{Category: CategoryPrograms, Name: "Google Chrome", Version: "120.0.6099.71", Vendor: "Google LLC"},
		NodeSoftware{Category: CategoryPrograms, Name: "7-Zip 23.01 (x64)", Version: "23.01", Vendor: "Igor Pavlov"},
		NodeSoftware{Category: CategoryPython, Name: "requests", Version: "2.31.0"})
	f.cpe(t, "CVE-2026-1000", SeverityCritical, "mozilla:firefox", []cpeRange{{EndExcluding: "130.0"}}, nil)
	f.cpe(t, "CVE-2026-1001", SeverityHigh, "google:chrome", []cpeRange{{EndExcluding: "119.0"}}, nil)
	f.cpe(t, "CVE-2026-1002", SeverityHigh, "7-zip:7-zip", nil, []string{"23.01"})
	f.synced(t, "PyPI")
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
	f.synced(t, "PyPI")
	require.NoError(t, f.matcher.MatchNode("N1"))
	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "N1").Error)
	assert.Equal(t, 2, state.NotAssessed)
	require.NotNil(t, state.MatchedAt)
}

// An ecosystem whose feed never synced has no advisories to match against;
// its packages are not assessed, not clean (Rocky before its first sync, or
// a mirror without that directory).
func TestMatchCountsUnsyncedEcosystemsAsNotAssessed(t *testing.T) {
	f := newMatchFixture(t)
	f.synced(t, "Debian")
	f.node(t, "N1", "rocky", "9.4", "9",
		NodeSoftware{Category: CategoryRPM, Name: "openssl", Version: "3.0.7-27.el9"},
		NodeSoftware{Category: CategoryRPM, Name: "bash", Version: "5.1.8-9.el9"})
	require.NoError(t, f.matcher.MatchNode("N1"))
	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "N1").Error)
	assert.Equal(t, 2, state.NotAssessed)
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

func TestMatchCPERecordsPossibleFindings(t *testing.T) {
	f := newMatchFixture(t)
	f.matcher.CPE = true
	f.windowsNode(t)
	require.NoError(t, f.matcher.MatchNode("W1"))

	got := f.findings(t, "W1")
	require.Len(t, got, 2)
	assert.Equal(t, "CVE-2026-1000", got[0].AdvisoryID)
	assert.Equal(t, ConfidencePossible, got[0].Confidence)
	assert.Equal(t, cpeEcosystem, got[0].Ecosystem)
	assert.Equal(t, "mozilla:firefox", got[0].Package)
	assert.Equal(t, "128.0.3", got[0].InstalledVersion)
	assert.Equal(t, "130.0", got[0].FixedVersion)
	assert.Equal(t, SeverityCritical, got[0].Severity)
	assert.Equal(t, "CVE-2026-1002", got[1].AdvisoryID, "7-Zip's publisher is no CPE vendor, but only one vendor ships 7-zip")

	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "W1").Error)
	assert.Zero(t, state.NotAssessed)
	assert.Equal(t, 1, state.Assessed, "only the Python package counts as assessed for scoring")
}

func TestMatchCPEIsNotAssessedWhileNVDIsOff(t *testing.T) {
	f := newMatchFixture(t)
	f.windowsNode(t) // NVD data left from an earlier run; --vuln-nvd-enabled is off now
	require.NoError(t, f.matcher.MatchNode("W1"))
	assert.Empty(t, f.findings(t, "W1"))
	var state NodeState
	require.NoError(t, f.db.First(&state, "node_uuid = ?", "W1").Error)
	assert.Equal(t, 3, state.NotAssessed)
	assert.Equal(t, 1, state.Assessed)
}

// Without a vendor (Homebrew, Chocolatey) a product two vendors ship matches
// neither: exact lookups only, no guessing.
func TestMatchCPENeedsAnUnambiguousProduct(t *testing.T) {
	f := newMatchFixture(t)
	f.matcher.CPE = true
	f.node(t, "M1", "darwin", "14.5", "14",
		NodeSoftware{Category: CategoryHomebrew, Name: "jq", Version: "1.6"},
		NodeSoftware{Category: CategoryHomebrew, Name: "openssl@3", Version: "3.0.1"})
	f.cpe(t, "CVE-2026-2000", SeverityHigh, "jqlang:jq", []cpeRange{{EndExcluding: "1.7.1"}}, nil)
	f.cpe(t, "CVE-2026-2001", SeverityHigh, "stedolan:jq", []cpeRange{{EndExcluding: "1.7"}}, nil)
	f.cpe(t, "CVE-2026-2002", SeverityHigh, "openssl:openssl", []cpeRange{{StartIncluding: "3.0.0", EndExcluding: "3.0.7"}}, nil)
	require.NoError(t, f.matcher.MatchNode("M1"))
	got := f.findings(t, "M1")
	require.Len(t, got, 1)
	assert.Equal(t, "openssl:openssl", got[0].Package)
}

// Apple's Terminal must not take on the CVEs of another vendor's "terminal":
// apple is a CPE vendor, so it contradicts the single-vendor fallback.
func TestMatchCPEKnownVendorBlocksTheFallback(t *testing.T) {
	f := newMatchFixture(t)
	f.matcher.CPE = true
	f.node(t, "M1", "darwin", "14.5", "14",
		NodeSoftware{Category: CategoryApps, Name: "Terminal", Version: "2.14", Vendor: "com.apple.Terminal"})
	f.cpe(t, "CVE-2026-3000", SeverityHigh, "apple:safari", []cpeRange{{EndExcluding: "17.5"}}, nil)
	f.cpe(t, "CVE-2026-3001", SeverityHigh, "acme:terminal", []cpeRange{{EndExcluding: "9.0"}}, nil)
	require.NoError(t, f.matcher.MatchNode("M1"))
	assert.Empty(t, f.findings(t, "M1"))
}

// A re-match that sees a raised severity before refreshFlags did records the
// escalation too.
func TestMatchRecordsEscalations(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12", NodeSoftware{Category: CategoryDeb, Name: "openssl", Version: "3.0.11-1"})
	f.advisory(t, "DSA-1-1", SeverityMedium, "Debian:12", "openssl", fixedAt("0", "3.0.13-1"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	require.NoError(t, f.db.Model(&Advisory{}).Where("id = ?", "DSA-1-1").Update("severity", SeverityCritical).Error)
	f.clock.advance(time.Hour)
	require.NoError(t, f.matcher.MatchNode("N1"))
	var got []Escalation
	require.NoError(t, f.db.Find(&got).Error)
	require.Len(t, got, 1)
	assert.Equal(t, SeverityMedium, got[0].PrevSeverity)
}

// Reopening is not news (the spec's "a reopen causes no re-alert"), even if
// the advisory grew more severe while the finding was resolved.
func TestMatchReopenRecordsNoEscalation(t *testing.T) {
	f := newMatchFixture(t)
	f.node(t, "N1", "debian", "12", "12", NodeSoftware{Category: CategoryDeb, Name: "openssl", Version: "3.0.11-1"})
	f.advisory(t, "DSA-1-1", SeverityMedium, "Debian:12", "openssl", fixedAt("0", "3.0.13-1"))
	require.NoError(t, f.matcher.MatchNode("N1"))
	f.clock.advance(time.Hour)
	require.NoError(t, f.db.Model(&NodeSoftware{}).Where("node_uuid = ?", "N1").Update("version", "3.0.13-1").Error)
	require.NoError(t, f.matcher.MatchNode("N1")) // resolved
	require.NoError(t, f.db.Model(&Advisory{}).Where("id = ?", "DSA-1-1").Update("severity", SeverityCritical).Error)
	f.clock.advance(time.Hour)
	require.NoError(t, f.db.Model(&NodeSoftware{}).Where("node_uuid = ?", "N1").Update("version", "3.0.11-1").Error)
	require.NoError(t, f.matcher.MatchNode("N1")) // reopened, now critical
	var n int64
	require.NoError(t, f.db.Model(&Escalation{}).Count(&n).Error)
	assert.Zero(t, n)
}
