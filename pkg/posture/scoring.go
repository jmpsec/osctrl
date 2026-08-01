package posture

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Control framework — maps posture data to SOC2 / ISO 27001 controls and
// evaluates each against a policy to produce a quantified risk score.
//
// Scoring model:
//
//   - A control may draw evidence from several posture categories (e.g.
//     software inventory accepts deb, rpm, Windows programs, Homebrew or
//     macOS apps). A category that is empty because it does not apply to
//     the platform (rpm on a Debian host) is NOT a finding — the control
//     passes as long as one applicable source has data.
//   - Controls whose categories were never collected are not evaluated at
//     all: they do not count as pass, warn or fail ("not applicable" rather
//     than "unknown risk").
//   - The total score is normalized: earned risk points divided by the
//     maximum possible points of the controls that were actually evaluated,
//     scaled to 0-100. This keeps scores comparable between platforms that
//     collect a different number of categories, and means a well-monitored
//     node is not penalized for having more checks.
//   - The risk level is exception-driven, the way an auditor reads a
//     report: any failing critical control (e.g. no disk encryption) makes
//     the node "critical" regardless of how many other controls pass; any
//     failing high control raises it to at least "high". Otherwise the
//     normalized score thresholds decide.
// ---------------------------------------------------------------------------

// Framework is the compliance framework a control belongs to.
type Framework string

const (
	FrameworkSOC2     Framework = "SOC2"
	FrameworkISO27001 Framework = "ISO27001"
)

// Severity is the risk weight of a failing control.
type Severity string

const (
	SeverityCritical Severity = "critical" // immediate risk, must fix
	SeverityHigh     Severity = "high"     // significant risk
	SeverityMedium   Severity = "medium"   // moderate risk
	SeverityLow      Severity = "low"      // minor risk
)

// ControlResult is the evaluation outcome for a single control.
type ControlResult struct {
	Category    string    `json:"category"`   // posture category the evidence came from
	ControlID   string    `json:"control_id"` // e.g. "A.8.24" or "CC6.6"
	Framework   Framework `json:"framework"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // "pass", "warn", "fail"
	Severity    Severity  `json:"severity"`
	Score       int       `json:"score"`  // 0 = pass, otherwise earned risk points
	Detail      string    `json:"detail"` // human-readable explanation
}

// PostureScore is the aggregate risk assessment for a node.
type PostureScore struct {
	NodeUUID   string          `json:"node_uuid"`
	Timestamp  time.Time       `json:"timestamp"`
	TotalScore int             `json:"total_score"` // 0-100 normalized, lower is better
	RiskLevel  string          `json:"risk_level"`  // "low", "medium", "high", "critical"
	Controls   []ControlResult `json:"controls"`
	PassCount  int             `json:"pass_count"`
	WarnCount  int             `json:"warn_count"`
	FailCount  int             `json:"fail_count"`
}

// RiskLevelFromScore converts a normalized score to a risk level.
func RiskLevelFromScore(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 15:
		return "medium"
	default:
		return "low"
	}
}

// SeverityWeight converts severity to risk points.
var SeverityWeight = map[Severity]int{
	SeverityCritical: 30,
	SeverityHigh:     20,
	SeverityMedium:   10,
	SeverityLow:      5,
}

// warnDivisor: a warning earns a quarter of the control's weight. Warnings
// are "needs review" items, not confirmed exposures — pricing them at half
// weight (as before) let a handful of review items outrank a real failure.
const warnDivisor = 4

// ---------------------------------------------------------------------------
// ScoreCalculator — takes posture records and evaluates them against
// policy rules to produce a PostureScore.
// ---------------------------------------------------------------------------

// ScoreCalculator evaluates posture data against compliance controls.
type ScoreCalculator struct {
	rules []ScoringRule
}

// ScoringRule defines how to evaluate one control from posture data.
type ScoringRule struct {
	// Categories lists every posture category that can provide evidence
	// for this control. The rule is evaluated when at least one of them
	// has been collected; mutually exclusive sources (deb vs rpm) belong
	// in the same rule so an empty inapplicable source is not a finding.
	Categories  []string  `json:"categories"`
	ControlID   string    `json:"control_id"`
	Framework   Framework `json:"framework"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	// Evaluate receives the collected categories (only those present for
	// the node) with their parsed rows and returns (status, detail).
	// status is "pass", "warn", or "fail".
	Evaluate func(data map[string][]map[string]interface{}) (status, detail string)
}

// NewScoreCalculator returns a calculator with all built-in rules.
func NewScoreCalculator() *ScoreCalculator {
	return &ScoreCalculator{rules: defaultRules()}
}

// Score evaluates all posture records and returns the aggregate score.
func (sc *ScoreCalculator) Score(records []NodePosture) PostureScore {
	score := PostureScore{
		Timestamp: time.Now(),
		Controls:  []ControlResult{},
	}

	// Build a lookup: category → parsed rows. A collected category with an
	// empty result is kept as an empty (non-nil) slice — "the query ran and
	// found nothing" is different from "never collected".
	categoryData := make(map[string][]map[string]interface{})
	for _, r := range records {
		var rows []map[string]interface{}
		if r.Summary != "" {
			_ = json.Unmarshal([]byte(r.Summary), &rows)
		}
		if rows == nil {
			// Try snapshot if summary was empty
			if r.Snapshot != "" {
				_ = json.Unmarshal([]byte(r.Snapshot), &rows)
			}
		}
		if rows == nil {
			rows = []map[string]interface{}{}
		}
		categoryData[r.Category] = rows
		if score.NodeUUID == "" {
			score.NodeUUID = r.NodeUUID
		}
	}

	earned := 0
	possible := 0
	for _, rule := range sc.rules {
		// Collect the evidence categories present for this node.
		data := make(map[string][]map[string]interface{})
		resultCategory := ""
		for _, cat := range rule.Categories {
			rows, exists := categoryData[cat]
			if !exists {
				continue
			}
			data[cat] = rows
			// Attribute the result to the first collected category with
			// data so UI drill-downs land on actual evidence.
			if resultCategory == "" || (len(categoryData[resultCategory]) == 0 && len(rows) > 0) {
				resultCategory = cat
			}
		}
		if len(data) == 0 {
			// Nothing collected for this control — not applicable, skip.
			continue
		}

		status, detail := rule.Evaluate(data)
		weight := SeverityWeight[rule.Severity]

		result := ControlResult{
			Category:    resultCategory,
			ControlID:   rule.ControlID,
			Framework:   rule.Framework,
			Title:       rule.Title,
			Description: rule.Description,
			Status:      status,
			Severity:    rule.Severity,
			Detail:      detail,
		}

		switch status {
		case "pass":
			result.Score = 0
			score.PassCount++
		case "warn":
			result.Score = weight / warnDivisor
			score.WarnCount++
		case "fail":
			result.Score = weight
			score.FailCount++
		}

		earned += result.Score
		possible += weight
		score.Controls = append(score.Controls, result)
	}

	if possible > 0 {
		score.TotalScore = int(math.Round(100 * float64(earned) / float64(possible)))
	}
	score.RiskLevel = riskLevel(score.TotalScore, score.Controls)
	return score
}

// riskLevel derives the risk level from the normalized score, escalated by
// the worst failing control: auditors reason in exceptions, and a single
// failed critical control (unencrypted disk) is a major nonconformity no
// matter how many low-weight controls pass around it.
func riskLevel(score int, controls []ControlResult) string {
	level := RiskLevelFromScore(score)
	for _, c := range controls {
		if c.Status != "fail" {
			continue
		}
		switch c.Severity {
		case SeverityCritical:
			return "critical"
		case SeverityHigh:
			if level == "low" || level == "medium" {
				level = "high"
			}
		}
	}
	return level
}

// ---------------------------------------------------------------------------
// Default scoring rules — mapped to ISO 27001:2022 Annex A and SOC2 TSC
// controls. Each rule evaluates the posture evidence and returns
// pass/warn/fail.
// ---------------------------------------------------------------------------

func defaultRules() []ScoringRule {
	return []ScoringRule{
		// --- Disk encryption at rest (A.8.24 / CC6.6) ---
		// Evidence arrives either as generic disk_encryption rows (Linux and
		// macOS: "encrypted" flag) or BitLocker rows ("protection_status"),
		// which Windows profiles store under the disk_encryption category.
		{
			Categories: []string{"disk_encryption", "bitlocker_info"},
			ControlID:  "A.8.24", Framework: FrameworkISO27001,
			Title:       "Disk encryption at rest",
			Description: "Data volumes must be encrypted at rest. Boot and recovery partitions are commonly unencrypted by design.",
			Severity:    SeverityCritical,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "warn", "No disk encryption data collected — cannot verify encryption at rest"
				}
				total := 0
				protected := 0
				osDriveUnprotected := false
				for _, row := range rows {
					total++
					if _, isBitlocker := row["protection_status"]; isBitlocker {
						// osquery bitlocker_info: protection_status 1 = on
						status := getStr(row, "protection_status")
						if status == "1" || strings.EqualFold(status, "On") || strings.EqualFold(status, "Protected") {
							protected++
						} else if strings.EqualFold(strings.TrimSuffix(getStr(row, "drive_letter"), ":"), "c") {
							osDriveUnprotected = true
						}
						continue
					}
					enc := getStr(row, "encrypted")
					if enc == "1" || strings.EqualFold(enc, "true") {
						protected++
					}
				}
				switch {
				case osDriveUnprotected:
					return "fail", "OS drive (C:) is not BitLocker-protected"
				case protected == 0:
					return "fail", fmt.Sprintf("None of %d disk(s) are encrypted", total)
				case protected < total:
					return "warn", fmt.Sprintf("%d of %d disk(s)/volume(s) are not encrypted — verify they hold no data (boot, swap and recovery partitions are commonly unencrypted)", total-protected, total)
				default:
					return "pass", fmt.Sprintf("All %d disk(s) are encrypted", total)
				}
			},
		},

		// --- Software inventory (A.5.9 / CC6.1) ---
		// One control fed by every package source. Sources are mutually
		// exclusive per platform (deb vs rpm, Homebrew is optional on
		// macOS), so an empty inapplicable source is not a finding: the
		// control passes when any source has data.
		{
			Categories: []string{"packages_deb", "packages_rpm", "packages_windows", "packages_apps", "packages_brew"},
			ControlID:  "A.5.9", Framework: FrameworkISO27001,
			Title:       "Software inventory",
			Description: "An inventory of installed software must be available for asset management and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				sourceLabels := map[string]string{
					"packages_deb":     "deb",
					"packages_rpm":     "rpm",
					"packages_windows": "programs",
					"packages_apps":    "apps",
					"packages_brew":    "brew",
				}
				parts := []string{}
				totalRows := 0
				for cat, rows := range data {
					if len(rows) == 0 {
						continue
					}
					totalRows += len(rows)
					parts = append(parts, fmt.Sprintf("%d %s", len(rows), sourceLabels[cat]))
				}
				if totalRows == 0 {
					return "warn", fmt.Sprintf("Package inventory collected from %d source(s) but empty — verify osquery table access", len(data))
				}
				sort.Strings(parts)
				return "pass", fmt.Sprintf("%d packages inventoried (%s)", totalRows, strings.Join(parts, ", "))
			},
		},

		// --- Users with real shells (A.8.2 / CC6.1) ---
		{
			Categories: []string{"users"},
			ControlID:  "A.8.2", Framework: FrameworkISO27001,
			Title:       "Interactive user accounts",
			Description: "Review users with login shells. Multiple UID-0 accounts or excessive interactive accounts increase attack surface.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "warn", "No user data collected"
				}
				rootUsers := 0
				for _, row := range rows {
					uid := getStr(row, "uid")
					if uid == "0" {
						rootUsers++
					}
				}
				if rootUsers > 1 {
					return "fail", fmt.Sprintf("%d users with UID 0 (root) have login shells — should be exactly 1", rootUsers)
				}
				if len(rows) > 20 {
					return "warn", fmt.Sprintf("%d interactive user accounts — review if all are necessary", len(rows))
				}
				return "pass", fmt.Sprintf("%d interactive user accounts, %d with root access", len(rows), rootUsers)
			},
		},

		// --- SSH authorized keys (A.5.17 / CC6.1) ---
		{
			Categories: []string{"ssh_keys"},
			ControlID:  "A.5.17", Framework: FrameworkISO27001,
			Title:       "SSH authorized keys",
			Description: "Review SSH key access. Keys for root or excessive keys increase unauthorized access risk.",
			Severity:    SeverityHigh,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No SSH authorized keys found"
				}
				rootKeys := 0
				for _, row := range rows {
					uid := getStr(row, "uid")
					if uid == "0" {
						rootKeys++
					}
				}
				if rootKeys > 0 {
					return "warn", fmt.Sprintf("%d SSH authorized key(s) for root (UID 0) — remove if not required", rootKeys)
				}
				return "pass", fmt.Sprintf("%d SSH authorized key(s), none for root", len(rows))
			},
		},

		// --- Listening ports (A.8.20 / CC6.6) ---
		// Plaintext-authentication services are always a failure. Services
		// that are legitimate on many servers but dangerous when exposed
		// (RDP, SMB, SNMP, VNC) are a warning to review exposure, not a
		// failure: RDP/SMB listen on effectively every Windows server.
		{
			Categories: []string{"listening_ports"},
			ControlID:  "A.8.20", Framework: FrameworkISO27001,
			Title:       "Open listening ports",
			Description: "Minimize open ports. Plaintext services must not run; remote-access services must not be exposed beyond trusted networks.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No listening ports"
				}
				plaintextPorts := map[string]string{
					"23": "telnet",
					"21": "ftp",
				}
				reviewPorts := map[string]string{
					"3389": "rdp",
					"445":  "smb",
					"161":  "snmp",
					"5900": "vnc",
				}
				plaintext := []string{}
				review := []string{}
				for _, row := range rows {
					port := getStr(row, "port")
					if svc, ok := plaintextPorts[port]; ok {
						plaintext = append(plaintext, svc)
					}
					if svc, ok := reviewPorts[port]; ok {
						review = append(review, svc)
					}
				}
				if len(plaintext) > 0 {
					return "fail", fmt.Sprintf("Plaintext service(s) listening: %s", strings.Join(dedupe(plaintext), ", "))
				}
				if len(review) > 0 {
					return "warn", fmt.Sprintf("Remote-access service(s) listening: %s — verify they are not exposed beyond trusted networks", strings.Join(dedupe(review), ", "))
				}
				if len(rows) > 50 {
					return "warn", fmt.Sprintf("%d listening ports — review if all are necessary", len(rows))
				}
				return "pass", fmt.Sprintf("%d listening ports, none on risky services", len(rows))
			},
		},

		// --- Patches / hotfixes (A.8.8 / CC7.1) ---
		{
			Categories: []string{"patches"},
			ControlID:  "A.8.8", Framework: FrameworkISO27001,
			Title:       "Security patches installed",
			Description: "Verify security patches are installed. Missing patches are exploitable vulnerabilities.",
			Severity:    SeverityHigh,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "warn", "No patch data collected — cannot verify patch status"
				}
				return "pass", fmt.Sprintf("%d patches installed", len(rows))
			},
		},

		// --- SUID binaries (A.8.9 / CC7.4) ---
		{
			Categories: []string{"suid_binaries"},
			ControlID:  "A.8.9", Framework: FrameworkISO27001,
			Title:       "SUID binaries",
			Description: "SUID binaries are privilege escalation vectors. Non-standard SUID binaries are high risk.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No SUID binaries found"
				}
				// Standard SUID binaries that are expected on Linux
				standardSUID := map[string]bool{
					"/usr/bin/sudo": true, "/usr/bin/su": true, "/usr/bin/passwd": true,
					"/usr/bin/chsh": true, "/usr/bin/chfn": true, "/usr/bin/newgrp": true,
					"/usr/bin/mount": true, "/usr/bin/umount": true, "/usr/bin/pkexec": true,
					"/usr/bin/gpasswd": true, "/usr/sbin/unix_chkpwd": true,
				}
				nonStandard := 0
				for _, row := range rows {
					path := getStr(row, "path")
					if !standardSUID[path] {
						nonStandard++
					}
				}
				if nonStandard > 5 {
					return "warn", fmt.Sprintf("%d non-standard SUID binaries — review for unnecessary privilege escalation paths", nonStandard)
				}
				return "pass", fmt.Sprintf("%d SUID binaries (%d standard, %d non-standard)", len(rows), len(rows)-nonStandard, nonStandard)
			},
		},

		// --- Startup items (A.8.9 / CC8.1) ---
		{
			Categories: []string{"startup_items"},
			ControlID:  "A.8.9", Framework: FrameworkISO27001,
			Title:       "Startup items / autostart",
			Description: "Review programs that run at startup. Unexpected startup items may indicate persistence.",
			Severity:    SeverityLow,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No startup items found"
				}
				if len(rows) > 30 {
					return "warn", fmt.Sprintf("%d startup items — review for unnecessary persistence", len(rows))
				}
				return "pass", fmt.Sprintf("%d startup items", len(rows))
			},
		},

		// --- Browser extensions (A.8.19 / CC6.6) ---
		{
			Categories: []string{"browser_extensions_chrome"},
			ControlID:  "A.8.19", Framework: FrameworkISO27001,
			Title:       "Chrome browser extensions",
			Description: "Browser extensions can access sensitive data. Review for unknown or malicious extensions.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No Chrome extensions found"
				}
				if len(rows) > 15 {
					return "warn", fmt.Sprintf("%d Chrome extensions across all profiles — review for data access risk", len(rows))
				}
				return "pass", fmt.Sprintf("%d Chrome extensions", len(rows))
			},
		},
		{
			Categories: []string{"browser_extensions_firefox"},
			ControlID:  "A.8.19", Framework: FrameworkISO27001,
			Title:       "Firefox browser add-ons",
			Description: "Firefox add-ons can access sensitive data. Review for unknown or malicious add-ons.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No Firefox add-ons found"
				}
				if len(rows) > 15 {
					return "warn", fmt.Sprintf("%d Firefox add-ons — review for data access risk", len(rows))
				}
				return "pass", fmt.Sprintf("%d Firefox add-ons", len(rows))
			},
		},

		// --- WiFi networks (A.8.21 / CC6.1) ---
		{
			Categories: []string{"wifi_networks"},
			ControlID:  "A.8.21", Framework: FrameworkISO27001,
			Title:       "Known WiFi networks",
			Description: "Review saved WiFi networks. Open or unsecured networks pose data interception risk.",
			Severity:    SeverityLow,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No saved WiFi networks"
				}
				open := 0
				for _, row := range rows {
					sec := getStr(row, "security_type")
					if sec == "" || strings.EqualFold(sec, "open") || strings.EqualFold(sec, "none") {
						open++
					}
				}
				if open > 0 {
					return "warn", fmt.Sprintf("%d of %d saved WiFi network(s) are open/unsecured", open, len(rows))
				}
				return "pass", fmt.Sprintf("%d saved WiFi networks, all secured", len(rows))
			},
		},

		// --- macOS sharing preferences (A.8.9 / CC6.1) ---
		{
			Categories: []string{"file_sharing"},
			ControlID:  "A.8.9", Framework: FrameworkISO27001,
			Title:       "macOS sharing services",
			Description: "File sharing, screen sharing, and remote login should be disabled unless explicitly required.",
			Severity:    SeverityMedium,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "warn", "No sharing preference data collected"
				}
				row := rows[0]
				enabled := []string{}
				for _, svc := range []string{"file_sharing", "screen_sharing", "remote_login", "remote_management", "internet_sharing", "printer_sharing"} {
					if getStr(row, svc) == "1" || strings.EqualFold(getStr(row, svc), "true") || strings.EqualFold(getStr(row, svc), "on") {
						enabled = append(enabled, svc)
					}
				}
				if len(enabled) > 0 {
					return "warn", fmt.Sprintf("Sharing service(s) enabled: %s — disable unless explicitly required", strings.Join(enabled, ", "))
				}
				return "pass", "No sharing services enabled"
			},
		},

		// --- Kernel modules (A.8.9 / CC7.4) — Linux servers ---
		{
			Categories: []string{"kernel_modules"},
			ControlID:  "A.8.9", Framework: FrameworkISO27001,
			Title:       "Loaded kernel modules",
			Description: "Review loaded kernel modules. Non-standard modules may indicate rootkits or unnecessary drivers.",
			Severity:    SeverityLow,
			Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
				rows := mergeRows(data)
				if len(rows) == 0 {
					return "pass", "No kernel modules loaded"
				}
				return "pass", fmt.Sprintf("%d kernel modules loaded", len(rows))
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mergeRows flattens the rows of every collected category, in stable
// category order.
func mergeRows(data map[string][]map[string]interface{}) []map[string]interface{} {
	cats := make([]string, 0, len(data))
	for cat := range data {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	var out []map[string]interface{}
	for _, cat := range cats {
		out = append(out, data[cat]...)
	}
	return out
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func getStr(row map[string]interface{}, key string) string {
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
