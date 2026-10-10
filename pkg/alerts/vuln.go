package alerts

// vuln.go — thresholds for vulnerability-finding rules (SourceVulnFinding).

import "strings"

// VulnMinSeverity values.
const (
	VulnMinKEV      = "kev"
	VulnMinCritical = "critical"
	VulnMinHigh     = "high"
	VulnMinMedium   = "medium"
	VulnMinLow      = "low"
	VulnMinAny      = "any"
)

// vulnThresholdRank orders the thresholds below "kev".
var vulnThresholdRank = map[string]int{
	VulnMinAny: 0, VulnMinLow: 1, VulnMinMedium: 2, VulnMinHigh: 3, VulnMinCritical: 4,
}

// vulnSeverityRank orders finding severities. "unknown" (and anything not
// listed) ranks 0, below "low", so only an "any" rule matches it.
var vulnSeverityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

func validVulnThreshold(min string) bool {
	_, ok := vulnThresholdRank[min]
	return ok || min == VulnMinKEV
}

// vulnMatches reports whether a finding meets a rule's threshold. "kev"
// matches only known-exploited findings; every other threshold also matches
// KEV findings whatever their CVSS severity, because exploitation in the
// wild outranks the score.
func vulnMatches(min, severity string, kev bool) bool {
	if min == VulnMinKEV {
		return kev
	}
	need, ok := vulnThresholdRank[min]
	if !ok {
		return false
	}
	return kev || vulnSeverityRank[severity] >= need
}

// normalizeVulnMin is the stored form of a threshold.
func normalizeVulnMin(min string) string {
	return strings.ToLower(strings.TrimSpace(min))
}
