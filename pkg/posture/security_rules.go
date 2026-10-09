package posture

import (
	"fmt"
	"strconv"
	"strings"
)

// These are technical evidence checks, not certification decisions. Framework
// references describe the control objective supported by the signal.
func securityRules() []ScoringRule {
	rules := []ScoringRule{
		securityStateRule("secure_boot", "A.8.9", FrameworkISO27001, "Secure Boot", "Verify boot integrity protection. Unsupported firmware requires review.", SeverityHigh, "secure_boot", []string{"1", "true"}, []string{"0", "false"}),
		securityStateRule("macos_firewall", "CC6.6", FrameworkSOC2, "macOS firewall", "Verify the application firewall is enabled; this does not assess its exceptions.", SeverityHigh, "global_state", []string{"1", "2"}, []string{"0"}),
		securityStateRule("gatekeeper", "CC6.8", FrameworkSOC2, "Gatekeeper application assessment", "Verify macOS assesses downloaded applications before execution.", SeverityHigh, "assessments_enabled", []string{"1", "true"}, []string{"0", "false"}),
		securityStateRule("system_integrity", "A.8.9", FrameworkISO27001, "System Integrity Protection", "Verify the overall macOS SIP protection flag, not individual allow flags.", SeverityHigh, "enabled", []string{"1", "true"}, []string{"0", "false"}),
		securityStateRule("windows_firewall", "CC6.6", FrameworkSOC2, "Windows firewall health", "Verify Windows Security Center reports a healthy firewall.", SeverityHigh, "firewall", []string{"good"}, []string{"poor", "snoozed"}),
		securityStateRule("windows_antivirus", "CC6.8", FrameworkSOC2, "Windows malware protection", "Verify Windows Security Center reports healthy antivirus protection.", SeverityHigh, "antivirus", []string{"good"}, []string{"poor", "snoozed"}),
		securityStateRule("windows_updates", "CC7.1", FrameworkSOC2, "Windows automatic updates", "Verify automatic update health. This does not establish patch currency or absence of vulnerabilities.", SeverityMedium, "autoupdate", []string{"good"}, []string{"poor", "snoozed"}),
		securityStateRule("windows_uac", "A.8.2", FrameworkISO27001, "User Account Control", "Verify Windows reports healthy elevation controls.", SeverityHigh, "user_account_control", []string{"good"}, []string{"poor", "snoozed"}),
		securityStateRule("password_storage", "A.5.17", FrameworkISO27001, "Reversible password storage", "Local security policy must not enable reversible password encryption.", SeverityHigh, "clear_text_password", []string{"0", "false"}, []string{"1", "true"}),
		securityStateRule("linux_aslr", "A.8.9", FrameworkISO27001, "Address space randomization", "Verify full Linux address space randomization (randomize_va_space=2).", SeverityMedium, "current_value", []string{"2"}, []string{"0", "1"}),
		securityStateRule("audit_service", "CC7.2", FrameworkSOC2, "Audit service availability", "Verify auditd or Windows Event Log is running. Rules, forwarding and retention require separate evidence.", SeverityMedium, "state", []string{"active", "running"}, []string{"inactive", "failed", "stopped"}),
		{
			RuleKey: "screen_lock", Categories: []string{"screen_lock"},
			ControlID: "A.8.1", Framework: FrameworkISO27001, Severity: SeverityHigh,
			Title:       "Screen lock authentication",
			Description: "Require a password on wake with at most a 60-second grace period. This local baseline covers only osquery's logged-in user context.",
			Evaluate:    evaluateScreenLock,
		},
		{
			RuleKey: "linux_mac", Categories: []string{"selinux", "apparmor"},
			ControlID: "A.8.3", Framework: FrameworkISO27001, Severity: SeverityMedium,
			Title:       "Mandatory access controls",
			Description: "Look for enforcing SELinux or AppArmor profiles. Empty alternative providers are not failures; profile coverage still requires review.",
			Evaluate:    evaluateMandatoryAccess,
		},
	}
	// sip_config also contains allow_* rows whose enabled semantics are the
	// inverse of the overall SIP row. Never treat those as overall protection.
	for i := range rules {
		if rules[i].RuleKey == "system_integrity" {
			base := rules[i].Evaluate
			rules[i].Evaluate = func(data map[string][]map[string]interface{}) (string, string) {
				var rows []map[string]interface{}
				for _, row := range mergeRows(data) {
					if getStr(row, "config_flag") == "sip" {
						rows = append(rows, row)
					}
				}
				return base(map[string][]map[string]interface{}{"system_integrity": rows})
			}
		}
	}
	return rules
}

func securityStateRule(key, control string, framework Framework, title, description string, severity Severity, field string, passing, failing []string) ScoringRule {
	states := map[string]string{}
	for _, value := range passing {
		states[value] = "pass"
	}
	for _, value := range failing {
		states[value] = "fail"
	}
	return ScoringRule{
		RuleKey: key, Categories: []string{key}, ControlID: control,
		Framework: framework, Title: title, Description: description, Severity: severity,
		Evaluate: func(data map[string][]map[string]interface{}) (string, string) {
			rows := mergeRows(data)
			unknown := len(rows) == 0
			for _, row := range rows {
				switch states[strings.ToLower(strings.TrimSpace(getStr(row, field)))] {
				case "fail":
					return "fail", fmt.Sprintf("%s reports an insecure state", title)
				case "pass":
				default:
					unknown = true
				}
			}
			if unknown {
				return "warn", fmt.Sprintf("Cannot verify %s: missing, unsupported or unrecognized %s evidence", title, field)
			}
			return "pass", fmt.Sprintf("%s meets the technical baseline", title)
		},
	}
}

func evaluateScreenLock(data map[string][]map[string]interface{}) (string, string) {
	rows := mergeRows(data)
	unknown := len(rows) == 0
	for _, row := range rows {
		enabled := strings.ToLower(strings.TrimSpace(getStr(row, "enabled")))
		grace, err := strconv.Atoi(strings.TrimSpace(getStr(row, "grace_period")))
		if enabled == "0" || enabled == "false" || (err == nil && (grace == -1 || grace > 60)) {
			return "fail", "Screen lock does not require prompt authentication on wake (local baseline: at most 60 seconds)"
		}
		if (enabled != "1" && enabled != "true") || err != nil || grace < 0 {
			unknown = true
		}
	}
	if unknown {
		return "warn", "Cannot verify screen lock in osquery's current logged-in user context"
	}
	return "pass", "Password required within 60 seconds of wake in the collected user context; other users and idle timeout are not assessed"
}

func evaluateMandatoryAccess(data map[string][]map[string]interface{}) (string, string) {
	for _, row := range data["selinux"] {
		if getStr(row, "key") == "enforce" && strings.TrimSpace(getStr(row, "value")) == "1" {
			return "pass", "SELinux is enforcing; policy coverage requires separate review"
		}
	}
	rows := data["apparmor"]
	if len(rows) > 0 {
		for _, row := range rows {
			if strings.ToLower(strings.TrimSpace(getStr(row, "mode"))) != "enforce" {
				return "warn", "AppArmor includes non-enforcing or unrecognized profiles and enforcing SELinux was not observed"
			}
		}
		return "pass", "Collected AppArmor profiles are enforcing; application coverage requires separate review"
	}
	return "warn", "No enforcing SELinux or AppArmor evidence; verify provider availability and host policy"
}
