package vulns

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jmpsec/osctrl/pkg/posture"
)

// posture.go — vulnerability findings as posture score evidence.

// EvidenceCategory is the synthetic posture category findings are scored under.
const EvidenceCategory = "vulnerabilities"

var _ posture.EvidenceSource = (*Reader)(nil)

// ScoringRules implements posture.EvidenceSource.
func (r *Reader) ScoringRules() []posture.ScoringRule {
	return []posture.ScoringRule{{
		RuleKey:     "known_vulnerabilities",
		Categories:  []string{EvidenceCategory},
		ControlID:   "A.8.8",
		Framework:   posture.FrameworkISO27001,
		Title:       "Known vulnerabilities",
		Description: "Installed packages affected by known vulnerabilities (OSV advisories, CISA KEV). Open confirmed findings only.",
		Severity:    posture.SeverityCritical,
		Grade:       gradeVulnerabilities,
	}}
}

// gradeVulnerabilities: KEV or critical fails at critical weight, high at
// high weight, anything else open warns. A pass is graded critical so a
// clean node's score counts the control at full weight.
func gradeVulnerabilities(data map[string][]map[string]interface{}) (string, string, posture.Severity) {
	rows := data[EvidenceCategory]
	if len(rows) != 1 {
		return "warn", "Vulnerability evidence is malformed", posture.SeverityMedium
	}
	count := func(key string) int {
		v, _ := rows[0][key].(float64)
		return int(v)
	}
	kev, critical, high := count("kev"), count("critical"), count("high")
	other := count("medium") + count("low") + count("unknown")
	switch {
	case kev > 0 || critical > 0:
		return "fail", fmt.Sprintf("%d known-exploited and %d critical open vulnerability findings", kev, critical), posture.SeverityCritical
	case high > 0:
		return "fail", fmt.Sprintf("%d high-severity open vulnerability findings", high), posture.SeverityHigh
	case other > 0:
		return "warn", fmt.Sprintf("%d medium, low or unknown-severity open vulnerability findings", other), posture.SeverityMedium
	case count("not_assessed") > 0:
		// Not assessed is never clean.
		return "warn", fmt.Sprintf("No open vulnerability findings, but %d packages could not be assessed", count("not_assessed")), posture.SeverityMedium
	}
	return "pass", "No open vulnerability findings in the matched inventory", posture.SeverityCritical
}

// ScoreEvidence implements posture.EvidenceSource: one record per node with
// the counts of its open confirmed findings.
//
// A node gets a record only once advisory data is loaded and the node either
// has findings, or has been matched with at least one assessed package.
// Anything less would let an unassessed node pass (Amazon Linux, an OS-only
// Windows node, an ecosystem whose feed never synced). A node with findings
// stays evaluated while an advisory sync has cleared its matched_at, so its
// score does not flicker after every sync.
func (r *Reader) ScoreEvidence(nodeUUIDs []string) (map[string][]posture.NodePosture, error) {
	out := map[string][]posture.NodePosture{}
	loaded, _, err := r.freshness()
	if err != nil {
		return nil, err
	}
	if !loaded || len(nodeUUIDs) == 0 {
		return out, nil
	}
	matched := map[string]bool{}
	notAssessed := map[string]int{}
	packages := map[string]int{}
	counts := map[string]map[string]int{}
	for chunk := range slices.Chunk(nodeUUIDs, queryChunk) {
		var states []NodeState
		if err := r.DB.Where("node_uuid IN ?", chunk).Find(&states).Error; err != nil {
			return nil, err
		}
		for _, s := range states {
			matched[s.NodeUUID] = s.MatchedAt != nil
			notAssessed[s.NodeUUID] = s.NotAssessed
		}
		var software []struct {
			NodeUUID string
			Total    int
		}
		if err := r.DB.Model(&NodeSoftware{}).Select("node_uuid, COUNT(*) AS total").
			Where("node_uuid IN ?", chunk).Group("node_uuid").Scan(&software).Error; err != nil {
			return nil, err
		}
		for _, s := range software {
			packages[s.NodeUUID] = s.Total
		}
		var rows []struct {
			NodeUUID string
			Severity string
			KEV      bool
			Total    int
		}
		if err := r.DB.Model(&Finding{}).
			Select("node_uuid, severity, kev, COUNT(*) AS total").
			Where("node_uuid IN ? AND resolved_at IS NULL AND confidence = ?", chunk, ConfidenceConfirmed).
			Group("node_uuid, severity, kev").
			Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			c := counts[row.NodeUUID]
			if c == nil {
				c = map[string]int{}
				counts[row.NodeUUID] = c
			}
			c[row.Severity] += row.Total
			if row.KEV {
				c["kev"] += row.Total
			}
		}
	}
	now := r.now()
	for _, uuid := range nodeUUIDs {
		c, hasFindings := counts[uuid]
		if !hasFindings && (!matched[uuid] || packages[uuid]-notAssessed[uuid] <= 0) {
			continue
		}
		summary, err := json.Marshal([]map[string]int{{
			SeverityCritical: c[SeverityCritical], SeverityHigh: c[SeverityHigh], SeverityMedium: c[SeverityMedium],
			SeverityLow: c[SeverityLow], SeverityUnknown: c[SeverityUnknown], "kev": c["kev"],
			"not_assessed": notAssessed[uuid],
		}})
		if err != nil {
			return nil, err
		}
		out[uuid] = []posture.NodePosture{{
			NodeUUID: uuid, Category: EvidenceCategory, RowCount: 1, Summary: string(summary), LastSeen: now,
		}}
	}
	return out, nil
}
