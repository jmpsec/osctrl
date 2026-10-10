package vulns

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redHatRecord is modeled on RHSA-2026:76750 as published in the OSV bucket.
const redHatRecord = `{
  "id": "RHSA-2026:76750",
  "modified": "2026-10-08T10:42:30.33938859Z",
  "published": "2026-10-07T00:00:00Z",
  "upstream": ["CVE-2026-19534", "CVE-2026-9496"],
  "summary": "Important: nodejs:22 security update",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
  "affected": [
    {"package": {"ecosystem": "Red Hat:enterprise_linux:9::appstream", "name": "nodejs", "purl": "pkg:rpm/redhat/nodejs"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:22.23.2-2.module+el9.8.0+24958+80b2ac6e"}]}]},
    {"package": {"ecosystem": "Red Hat:rhel_eus:9.2::appstream", "name": "nodejs"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:22.0.0-1"}]}]}
  ],
  "references": [{"type": "ADVISORY", "url": "https://access.redhat.com/errata/RHSA-2026:76750"}]
}`

func TestParseOSVRedHat(t *testing.T) {
	p, err := parseOSV([]byte(redHatRecord))
	require.NoError(t, err)
	assert.Equal(t, "RHSA-2026:76750", p.Advisory.ID)
	assert.Equal(t, 7.5, p.Advisory.CVSSScore)
	assert.Equal(t, SeverityHigh, p.Advisory.Severity)
	require.Len(t, p.Affected, 1, "the EUS stream is not matched")
	assert.Equal(t, "Red Hat:9", p.Affected[0].Ecosystem)
	assert.Equal(t, "nodejs", p.Affected[0].Package)
	var ranges []Range
	require.NoError(t, json.Unmarshal([]byte(p.Affected[0].Ranges), &ranges))
	assert.Equal(t, "1:22.23.2-2.module+el9.8.0+24958+80b2ac6e", ranges[0].Events[1].Fixed)

	var aliases []string
	for _, a := range p.Aliases {
		aliases = append(aliases, a.Alias)
	}
	assert.ElementsMatch(t, []string{"CVE-2026-19534", "CVE-2026-9496"}, aliases, "CVE ids come from upstream as well as aliases")
	var refs []string
	require.NoError(t, json.Unmarshal([]byte(p.Advisory.RefURLs), &refs))
	assert.Equal(t, []string{"https://access.redhat.com/errata/RHSA-2026:76750"}, refs)
}

func TestParseOSVUbuntuWithoutSeverity(t *testing.T) {
	p, err := parseOSV([]byte(`{
	  "id": "UBUNTU-CVE-2026-53215", "modified": "2026-10-09T19:42:00Z", "upstream": ["CVE-2026-53215"],
	  "affected": [
	    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "linux-hwe-edge"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], "versions": ["5.15.0-1.1"]},
	    {"package": {"ecosystem": "Ubuntu:Pro:22.04:LTS", "name": "linux-hwe-edge"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
	  ]}`))
	require.NoError(t, err)
	assert.Equal(t, SeverityUnknown, p.Advisory.Severity, "no CVSS published means unknown, not low")
	require.Len(t, p.Affected, 1)
	assert.Equal(t, "Ubuntu:22.04", p.Affected[0].Ecosystem)
	assert.JSONEq(t, `["5.15.0-1.1"]`, p.Affected[0].Versions)
}

func TestParseOSVNormalizesPyPINamesAndSelfCVE(t *testing.T) {
	p, err := parseOSV([]byte(`{"id": "CVE-2026-1000", "modified": "2026-10-01T00:00:00Z",
	  "affected": [{"package": {"ecosystem": "PyPI", "name": "Django_REST.framework"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.15.2"}]}]}]}`))
	require.NoError(t, err)
	assert.Equal(t, "django-rest-framework", p.Affected[0].Package)
	require.Len(t, p.Aliases, 1)
	assert.Equal(t, "CVE-2026-1000", p.Aliases[0].Alias, "a CVE-named record is its own KEV key")
}

func TestParseOSVWithdrawn(t *testing.T) {
	p, err := parseOSV([]byte(`{"id": "DSA-1-1", "modified": "2026-10-01T00:00:00Z", "withdrawn": "2026-10-02T00:00:00Z", "affected": []}`))
	require.NoError(t, err)
	assert.True(t, p.Withdrawn)
}

func TestParseOSVRejectsRecordsWithoutID(t *testing.T) {
	_, err := parseOSV([]byte(`{"modified": "2026-10-01T00:00:00Z"}`))
	assert.Error(t, err)
	_, err = parseOSV([]byte(`not json`))
	assert.Error(t, err)
}

func TestSeverityFromScore(t *testing.T) {
	assert.Equal(t, SeverityCritical, severityFromScore(9.8))
	assert.Equal(t, SeverityCritical, severityFromScore(9.0))
	assert.Equal(t, SeverityHigh, severityFromScore(7.0))
	assert.Equal(t, SeverityMedium, severityFromScore(4.0))
	assert.Equal(t, SeverityLow, severityFromScore(0.1))
	assert.Equal(t, SeverityUnknown, severityFromScore(0))
}

func TestCVSSScoreVersions(t *testing.T) {
	s, ok := cvssScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.True(t, ok)
	assert.Equal(t, 9.8, s)
	_, ok = cvssScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	assert.True(t, ok)
	_, ok = cvssScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	assert.False(t, ok, "CVSS v2 is not used")
}
