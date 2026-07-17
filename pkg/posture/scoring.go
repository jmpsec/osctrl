package posture

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Control framework — maps posture data to SOC2 / ISO 27001 controls and
// evaluates each against a policy to produce a quantified risk score.
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
	Category    string    `json:"category"`   // posture category (e.g. "disk_encryption")
	ControlID   string    `json:"control_id"` // e.g. "A.8.5" or "CC6.6"
	Framework   Framework `json:"framework"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // "pass", "warn", "fail"
	Severity    Severity  `json:"severity"`
	Score       int       `json:"score"`  // 0 = pass, 1-100 = risk points
	Detail      string    `json:"detail"` // human-readable explanation
}

// PostureScore is the aggregate risk assessment for a node.
type PostureScore struct {
	NodeUUID   string          `json:"node_uuid"`
	Timestamp  time.Time       `json:"timestamp"`
	TotalScore int             `json:"total_score"` // 0-100, lower is better
	RiskLevel  string          `json:"risk_level"`  // "low", "medium", "high", "critical"
	Controls   []ControlResult `json:"controls"`
	PassCount  int             `json:"pass_count"`
	WarnCount  int             `json:"warn_count"`
	FailCount  int             `json:"fail_count"`
}

// RiskLevelFromScore converts a numeric score to a risk level.
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

// ---------------------------------------------------------------------------
// ScoreCalculator — takes posture records and evaluates them against
// policy rules to produce a PostureScore.
// ---------------------------------------------------------------------------

// ScoreCalculator evaluates posture data against compliance controls.
type ScoreCalculator struct {
	rules []ScoringRule
}

// ScoringRule defines how to evaluate a posture category.
type ScoringRule struct {
	Category    string    `json:"category"`
	ControlID   string    `json:"control_id"`
	Framework   Framework `json:"framework"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	// Evaluate receives the parsed rows from the posture summary and
	// returns (status, detail). status is "pass", "warn", or "fail".
	Evaluate func(rows []map[string]interface{}) (status, detail string)
}

// NewScoreCalculator returns a calculator with all built-in rules.
func NewScoreCalculator() *ScoreCalculator {
	return &ScoreCalculator{rules: defaultRules()}
}

// Score evaluates all posture records and returns the aggregate score.
func (sc *ScoreCalculator) Score(records []NodePosture) PostureScore {
	score := PostureScore{
		Timestamp: time.Now(),
	}

	// Build a lookup: category → parsed rows
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
		categoryData[r.Category] = rows
		if score.NodeUUID == "" {
			score.NodeUUID = r.NodeUUID
		}
	}

	totalScore := 0
	for _, rule := range sc.rules {
		rows, exists := categoryData[rule.Category]
		if !exists {
			// Category not collected — skip (can't evaluate what we don't have)
			continue
		}

		status, detail := rule.Evaluate(rows)
		weight := SeverityWeight[rule.Severity]

		result := ControlResult{
			Category:    rule.Category,
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
			result.Score = weight / 2
			score.WarnCount++
		case "fail":
			result.Score = weight
			score.FailCount++
		}

		totalScore += result.Score
		score.Controls = append(score.Controls, result)
	}

	if totalScore > 100 {
		totalScore = 100
	}
	score.TotalScore = totalScore
	score.RiskLevel = RiskLevelFromScore(totalScore)
	return score
}

// ---------------------------------------------------------------------------
// Default scoring rules — mapped to SOC2 TSC and ISO 27001 Annex A controls.
// Each rule evaluates the posture data and returns pass/warn/fail.
// ---------------------------------------------------------------------------

func defaultRules() []ScoringRule {
	return []ScoringRule{
		// --- Disk Encryption (A.8.5 / CC6.6) ---
		{
			Category: "disk_encryption", ControlID: "A.8.5", Framework: FrameworkISO27001,
			Title:       "Disk encryption at rest",
			Description: "All disks must be encrypted. Unencrypted disks expose data at rest.",
			Severity:    SeverityCritical,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No disk encryption data collected — cannot verify"
				}
				unencrypted := 0
				for _, row := range rows {
					enc := getStr(row, "encrypted")
					if enc == "0" || strings.EqualFold(enc, "false") || enc == "" {
						unencrypted++
					}
				}
				if unencrypted > 0 {
					return "fail", fmt.Sprintf("%d of %d disk(s) are not encrypted", unencrypted, len(rows))
				}
				return "pass", fmt.Sprintf("All %d disk(s) are encrypted", len(rows))
			},
		},

		// --- Disk Encryption Windows (bitlocker_info) ---
		{
			Category: "bitlocker_info", ControlID: "A.8.5", Framework: FrameworkISO27001,
			Title:       "BitLocker disk encryption",
			Description: "BitLocker protection must be active on all drives.",
			Severity:    SeverityCritical,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No BitLocker data collected"
				}
				unprotected := 0
				for _, row := range rows {
					status := getStr(row, "protection_status")
					if status != "On" && !strings.EqualFold(status, "Protected") {
						unprotected++
					}
				}
				if unprotected > 0 {
					return "fail", fmt.Sprintf("%d of %d drive(s) lack BitLocker protection", unprotected, len(rows))
				}
				return "pass", fmt.Sprintf("All %d drive(s) have BitLocker protection", len(rows))
			},
		},

		// --- Users with real shells (A.5.15 / CC6.1) ---
		{
			Category: "users", ControlID: "A.5.15", Framework: FrameworkISO27001,
			Title:       "Interactive user accounts",
			Description: "Review users with login shells. Excessive interactive accounts increase attack surface.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
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

		// --- SSH authorized keys (A.5.37 / CC6.7) ---
		{
			Category: "ssh_keys", ControlID: "A.5.37", Framework: FrameworkISO27001,
			Title:       "SSH authorized keys",
			Description: "Review SSH key access. Keys for root or excessive keys increase unauthorized access risk.",
			Severity:    SeverityHigh,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
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

		// --- Listening ports (A.5.15 / CC6.1) ---
		{
			Category: "listening_ports", ControlID: "A.5.15", Framework: FrameworkISO27001,
			Title:       "Open listening ports",
			Description: "Minimize open ports. Unexpected services increase attack surface.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "pass", "No listening ports"
				}
				// Flag well-known dangerous ports
				dangerousPorts := map[string]bool{
					"23":   true, // telnet
					"21":   true, // ftp
					"3389": true, // rdp (only dangerous if exposed)
					"445":  true, // smb
					"161":  true, // snmp
				}
				dangerCount := 0
				for _, row := range rows {
					port := getStr(row, "port")
					if dangerousPorts[port] {
						dangerCount++
					}
				}
				if dangerCount > 0 {
					return "fail", fmt.Sprintf("%d listening port(s) on dangerous services (telnet/ftp/rdp/smb/snmp)", dangerCount)
				}
				if len(rows) > 50 {
					return "warn", fmt.Sprintf("%d listening ports — review if all are necessary", len(rows))
				}
				return "pass", fmt.Sprintf("%d listening ports, none on dangerous services", len(rows))
			},
		},

		// --- Patches / hotfixes (A.8.8 / CC7.1) ---
		{
			Category: "patches", ControlID: "A.8.8", Framework: FrameworkISO27001,
			Title:       "Security patches installed",
			Description: "Verify security patches are installed. Missing patches are exploitable vulnerabilities.",
			Severity:    SeverityHigh,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No patch data collected — cannot verify patch status"
				}
				return "pass", fmt.Sprintf("%d patches installed", len(rows))
			},
		},

		// --- SUID binaries (A.8.9 / CC7.4) ---
		{
			Category: "suid_binaries", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "SUID binaries",
			Description: "SUID binaries are privilege escalation vectors. Non-standard SUID binaries are high risk.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
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
			Category: "startup_items", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "Startup items / autostart",
			Description: "Review programs that run at startup. Unexpected startup items may indicate persistence.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "pass", "No startup items found"
				}
				if len(rows) > 30 {
					return "warn", fmt.Sprintf("%d startup items — review for unnecessary persistence", len(rows))
				}
				return "pass", fmt.Sprintf("%d startup items", len(rows))
			},
		},

		// --- Browser extensions (A.8.9 / CC6.6) ---
		{
			Category: "browser_extensions_chrome", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "Chrome browser extensions",
			Description: "Browser extensions can access sensitive data. Review for unknown or malicious extensions.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
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
			Category: "browser_extensions_firefox", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "Firefox browser add-ons",
			Description: "Firefox add-ons can access sensitive data. Review for unknown or malicious add-ons.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "pass", "No Firefox add-ons found"
				}
				if len(rows) > 15 {
					return "warn", fmt.Sprintf("%d Firefox add-ons — review for data access risk", len(rows))
				}
				return "pass", fmt.Sprintf("%d Firefox add-ons", len(rows))
			},
		},

		// --- WiFi networks (A.8.9 / CC6.1) ---
		{
			Category: "wifi_networks", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "Known WiFi networks",
			Description: "Review saved WiFi networks. Open or unsecured networks pose data interception risk.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
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
			Category: "file_sharing", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "macOS sharing services",
			Description: "File sharing, screen sharing, and remote login should be disabled unless explicitly required.",
			Severity:    SeverityMedium,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No sharing preference data collected"
				}
				if len(rows) == 0 {
					return "pass", "No sharing data"
				}
				row := rows[0]
				enabled := []string{}
				for _, svc := range []string{"file_sharing", "screen_sharing", "remote_management", "internet_sharing", "printer_sharing"} {
					if getStr(row, svc) == "1" || strings.EqualFold(getStr(row, svc), "true") || strings.EqualFold(getStr(row, svc), "on") {
						enabled = append(enabled, svc)
					}
				}
				if len(enabled) > 2 {
					return "warn", fmt.Sprintf("Multiple sharing services enabled: %s", strings.Join(enabled, ", "))
				}
				if len(enabled) > 0 {
					return "pass", fmt.Sprintf("Sharing services enabled: %s", strings.Join(enabled, ", "))
				}
				return "pass", "No sharing services enabled"
			},
		},

		// --- Kernel modules (A.8.9 / CC7.4) — Linux servers ---
		{
			Category: "kernel_modules", ControlID: "A.8.9", Framework: FrameworkISO27001,
			Title:       "Loaded kernel modules",
			Description: "Review loaded kernel modules. Non-standard modules may indicate rootkits or unnecessary drivers.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "pass", "No kernel modules loaded"
				}
				return "pass", fmt.Sprintf("%d kernel modules loaded", len(rows))
			},
		},

		// --- Installed packages (A.8.7 / CC7.1) ---
		{
			Category: "packages_deb", ControlID: "A.8.7", Framework: FrameworkISO27001,
			Title:       "Installed packages (DEB)",
			Description: "Track installed packages for inventory and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No package data collected"
				}
				return "pass", fmt.Sprintf("%d packages installed", len(rows))
			},
		},
		{
			Category: "packages_rpm", ControlID: "A.8.7", Framework: FrameworkISO27001,
			Title:       "Installed packages (RPM)",
			Description: "Track installed packages for inventory and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No package data collected"
				}
				return "pass", fmt.Sprintf("%d packages installed", len(rows))
			},
		},
		{
			Category: "packages_windows", ControlID: "A.8.7", Framework: FrameworkISO27001,
			Title:       "Installed programs (Windows)",
			Description: "Track installed programs for inventory and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No program data collected"
				}
				return "pass", fmt.Sprintf("%d programs installed", len(rows))
			},
		},
		{
			Category: "packages_brew", ControlID: "A.8.7", Framework: FrameworkISO27001,
			Title:       "Homebrew packages",
			Description: "Track Homebrew packages for inventory and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No Homebrew package data collected"
				}
				return "pass", fmt.Sprintf("%d Homebrew packages installed", len(rows))
			},
		},
		{
			Category: "packages_apps", ControlID: "A.8.7", Framework: FrameworkISO27001,
			Title:       "Installed applications (macOS)",
			Description: "Track installed macOS applications for inventory and vulnerability assessment.",
			Severity:    SeverityLow,
			Evaluate: func(rows []map[string]interface{}) (string, string) {
				if len(rows) == 0 {
					return "warn", "No application data collected"
				}
				return "pass", fmt.Sprintf("%d applications installed", len(rows))
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
