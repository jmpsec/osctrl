package vulns

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

const (
	maxSummaryLen = 2048
	maxDetailsLen = 16 << 10
	maxReferences = 50
)

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRecord struct {
	ID        string        `json:"id"`
	Modified  time.Time     `json:"modified"`
	Published time.Time     `json:"published"`
	Withdrawn *time.Time    `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Upstream  []string      `json:"upstream"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges   []Range       `json:"ranges"`
		Versions []string      `json:"versions"`
		Severity []osvSeverity `json:"severity"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// parsedAdvisory is everything one OSV record contributes to the database.
type parsedAdvisory struct {
	Advisory  Advisory
	Aliases   []Alias
	Affected  []Affected
	Withdrawn bool
}

// parseOSV converts one OSV JSON record. Affected entries in ecosystems
// osctrl does not match are dropped; storeAdvisory keeps no record that is
// left with none.
func parseOSV(raw []byte) (parsedAdvisory, error) {
	var rec osvRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return parsedAdvisory{}, err
	}
	if rec.ID == "" {
		return parsedAdvisory{}, errors.New("record has no id")
	}
	p := parsedAdvisory{Withdrawn: rec.Withdrawn != nil}
	p.Advisory = Advisory{
		ID:        clipTo(rec.ID, 128),
		Source:    AdvisorySourceOSV,
		Summary:   clipTo(rec.Summary, maxSummaryLen),
		Details:   clipTo(rec.Details, maxDetailsLen),
		Published: rec.Published,
		Modified:  rec.Modified,
		Severity:  SeverityUnknown,
	}

	vectors := append([]osvSeverity(nil), rec.Severity...)
	for _, a := range rec.Affected {
		vectors = append(vectors, a.Severity...)
	}
	if vector, score, ok := bestScore(vectors); ok {
		p.Advisory.CVSSVector, p.Advisory.CVSSScore = clip(vector), score
		p.Advisory.Severity = severityFromScore(score)
	}

	refs := []string{}
	for _, r := range rec.References {
		if r.URL != "" && len(refs) < maxReferences {
			refs = append(refs, r.URL)
		}
	}
	refJSON, _ := json.Marshal(refs)
	p.Advisory.RefURLs = string(refJSON)

	seen := map[string]bool{}
	ids := append(append([]string(nil), rec.Aliases...), rec.Upstream...)
	if strings.HasPrefix(rec.ID, "CVE-") {
		ids = append(ids, rec.ID)
	}
	for _, id := range ids {
		if id == "" || seen[id] || len(id) > 128 {
			continue
		}
		seen[id] = true
		p.Aliases = append(p.Aliases, Alias{AdvisoryID: p.Advisory.ID, Alias: id})
	}

	for _, a := range rec.Affected {
		key := AdvisoryKey(a.Package.Ecosystem)
		if key == "" || a.Package.Name == "" || (len(a.Ranges) == 0 && len(a.Versions) == 0) {
			continue
		}
		ranges, _ := json.Marshal(a.Ranges)
		versions, _ := json.Marshal(a.Versions)
		p.Affected = append(p.Affected, Affected{
			AdvisoryID: p.Advisory.ID,
			Ecosystem:  key,
			Package:    clip(PackageKey(key, a.Package.Name)),
			Ranges:     string(ranges),
			Versions:   string(versions),
		})
	}
	return p, nil
}

// bestScore picks the first scorable CVSS v3 vector, else the first v4.
func bestScore(sev []osvSeverity) (string, float64, bool) {
	for _, want := range []string{"CVSS_V3", "CVSS_V4"} {
		for _, s := range sev {
			if s.Type != want {
				continue
			}
			if score, ok := cvssScore(s.Score); ok {
				return s.Score, score, true
			}
		}
	}
	return "", 0, false
}

// cvssScore computes a base score from a CVSS v3.0, v3.1 or v4.0 vector.
func cvssScore(vector string) (float64, bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := cvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := cvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := cvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.Score(), true
	}
	return 0, false
}

// severityFromScore maps a CVSS score to the qualitative rating scale.
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}
