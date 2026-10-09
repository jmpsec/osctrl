package posture

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecuritySignals(t *testing.T) {
	tests := []struct {
		category, rows, status string
	}{
		{"secure_boot", `[{"secure_boot":1}]`, "pass"},
		{"secure_boot", `[{"secure_boot":"0"}]`, "fail"},
		{"secure_boot", `[{"secure_boot":-1}]`, "warn"},
		{"macos_firewall", `[{"global_state":"1"}]`, "pass"},
		{"macos_firewall", `[{"global_state":2}]`, "pass"},
		{"macos_firewall", `[{"global_state":"0"}]`, "fail"},
		{"gatekeeper", `[{"assessments_enabled":true}]`, "pass"},
		{"gatekeeper", `[{"assessments_enabled":false}]`, "fail"},
		{"system_integrity", `[{"config_flag":"sip","enabled":"1"},{"config_flag":"allow_untrusted_kexts","enabled":"0"}]`, "pass"},
		{"system_integrity", `[{"config_flag":"sip","enabled":"0"},{"config_flag":"allow_untrusted_kexts","enabled":"1"}]`, "fail"},
		{"system_integrity", `[{"config_flag":"allow_untrusted_kexts","enabled":"1"}]`, "warn"},
		{"windows_firewall", `[{"firewall":"Good"}]`, "pass"},
		{"windows_firewall", `[{"firewall":"Poor"}]`, "fail"},
		{"windows_antivirus", `[{"antivirus":"Good"}]`, "pass"},
		{"windows_antivirus", `[{"antivirus":"Snoozed"}]`, "fail"},
		{"windows_antivirus", `[{"antivirus":"Error"}]`, "warn"},
		{"windows_antivirus", `[{"antivirus":"Not Monitored"}]`, "warn"},
		{"windows_updates", `[{"autoupdate":"Good"}]`, "pass"},
		{"windows_updates", `[{"autoupdate":"Poor"}]`, "fail"},
		{"windows_uac", `[{"user_account_control":"Good"}]`, "pass"},
		{"windows_uac", `[{"user_account_control":"Poor"}]`, "fail"},
		{"password_storage", `[{"clear_text_password":"0"}]`, "pass"},
		{"password_storage", `[{"clear_text_password":"1"}]`, "fail"},
		{"linux_aslr", `[{"current_value":"2"}]`, "pass"},
		{"linux_aslr", `[{"current_value":"1"}]`, "fail"},
		{"linux_aslr", `[{"current_value":"0"}]`, "fail"},
		{"audit_service", `[{"state":"RUNNING"}]`, "pass"},
		{"audit_service", `[{"state":"active"}]`, "pass"},
		{"audit_service", `[{"state":"STOPPED"}]`, "fail"},
		{"audit_service", `[{"state":"failed"}]`, "fail"},
		{"audit_service", `[{"state":"activating"}]`, "warn"},
		{"screen_lock", `[{"enabled":1,"grace_period":0}]`, "pass"},
		{"screen_lock", `[{"enabled":"1","grace_period":"60"}]`, "pass"},
		{"screen_lock", `[{"enabled":"1","grace_period":"61"}]`, "fail"},
		{"screen_lock", `[{"enabled":"0","grace_period":"0"}]`, "fail"},
		{"screen_lock", `[{"enabled":"1","grace_period":"-1"}]`, "fail"},
		{"screen_lock", `[{"enabled":"1"}]`, "warn"},
		{"screen_lock", `[{"enabled":"1","grace_period":"-2"}]`, "warn"},
		{"screen_lock", `[{"enabled":"1","grace_period":"unknown"}]`, "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.category+"/"+tt.rows, func(t *testing.T) {
			score := NewScoreCalculator().Score([]NodePosture{{Category: tt.category, Summary: tt.rows}})
			if len(score.Controls) != 1 || score.Controls[0].Status != tt.status {
				t.Fatalf("want %s, got %+v", tt.status, score.Controls)
			}
			if tt.status == "fail" && (score.TotalScore != 100 || score.RiskLevel != "critical") {
				t.Fatalf("failure did not contribute to aggregate risk: %+v", score)
			}
		})
	}
}

func TestSecuritySignalsDoNotPassMissingOrMalformedEvidence(t *testing.T) {
	for _, rule := range securityRules() {
		for _, category := range rule.Categories {
			for _, raw := range []string{"", "[]", "null", "[{}]", "[null]", `[{"enabled":1}`, `[{"enabled":1},null]`} {
				t.Run(category+"/"+raw, func(t *testing.T) {
					score := NewScoreCalculator().Score([]NodePosture{{Category: category, Summary: raw}})
					if len(score.Controls) != 1 || score.Controls[0].Status != "warn" {
						t.Fatalf("missing or malformed evidence should warn: %+v", score.Controls)
					}
				})
			}
		}
	}
	if score := NewScoreCalculator().Score(nil); len(score.Controls) != 0 {
		t.Fatalf("uncollected controls should remain unevaluated: %+v", score)
	}
}

func TestSecuritySignalFailureDominatesUnknownRows(t *testing.T) {
	score := NewScoreCalculator().Score([]NodePosture{{Category: "windows_antivirus", Summary: `[{"antivirus":"Good"},{"antivirus":"Error"},{"antivirus":"Poor"}]`}})
	if score.Controls[0].Status != "fail" {
		t.Fatalf("known failure must dominate unknown evidence: %+v", score)
	}
	score = NewScoreCalculator().Score([]NodePosture{{Category: "windows_antivirus", Summary: `[{"antivirus":"Good"},{"antivirus":"Error"}]`}})
	if score.Controls[0].Status != "warn" {
		t.Fatalf("healthy row must not mask unknown evidence: %+v", score)
	}
}

func TestMandatoryAccessAlternativeProviders(t *testing.T) {
	tests := []struct {
		selinux, apparmor, status string
	}{
		{`[{"key":"enforce","value":"1\n"}]`, `[]`, "pass"},
		{`[]`, `[{"mode":"enforce"}]`, "pass"},
		{`[{"key":"enforce","value":"0"}]`, `[{"mode":"enforce"}]`, "pass"},
		{`[]`, `[{"mode":"enforce"},{"mode":"complain"}]`, "warn"},
		{`[{"key":"enforce","value":"1"}]`, `[{"mode":"complain"}]`, "pass"},
		{`[{"key":"unrelated","value":"1"}]`, `[]`, "warn"},
		{`[{"key":"enforce","value":"0"}]`, `[]`, "warn"},
		{`[]`, `[]`, "warn"},
	}
	for _, tt := range tests {
		score := NewScoreCalculator().Score([]NodePosture{
			{Category: "selinux", Summary: tt.selinux},
			{Category: "apparmor", Summary: tt.apparmor},
		})
		if len(score.Controls) != 1 || score.Controls[0].Status != tt.status {
			t.Errorf("%+v: got %+v", tt, score.Controls)
		}
	}
}

func TestScoringUsesFullSnapshotAndFlagsIncompleteEvidence(t *testing.T) {
	rows := make([]map[string]interface{}, 101)
	for i := range rows {
		rows[i] = map[string]interface{}{"port": "443"}
	}
	rows[100]["port"] = "23"
	record := postureRecord(t, "listening_ports", rows[:100])
	record.RowCount = len(rows)
	full, _ := json.Marshal(rows)
	record.Snapshot = string(full)
	score := NewScoreCalculator().Score([]NodePosture{record})
	if score.Controls[0].Status != "fail" {
		t.Fatalf("failure beyond the summary limit was missed: %+v", score)
	}
	for _, snapshot := range []string{"", string(full[:len(full)-10])} {
		record.Snapshot = snapshot
		score = NewScoreCalculator().Score([]NodePosture{record})
		if score.Controls[0].Status != "warn" || !strings.Contains(score.Controls[0].Detail, "incomplete") {
			t.Fatalf("incomplete evidence should warn: %+v", score)
		}
	}
	record.Summary = `[{"port":"23"}]`
	score = NewScoreCalculator().Score([]NodePosture{record})
	if score.Controls[0].Status != "fail" {
		t.Fatalf("incomplete evidence must not downgrade a confirmed failure: %+v", score)
	}
	for _, record := range []NodePosture{
		{Category: "secure_boot", Summary: "invalid", Snapshot: `[{"secure_boot":"1"}]`, RowCount: 1},
		{Category: "secure_boot", Summary: `{"secure_boot":"1"}`, RowCount: 1},
	} {
		if score := NewScoreCalculator().Score([]NodePosture{record}); score.Controls[0].Status != "pass" {
			t.Fatalf("valid fallback or legacy object should be usable: %+v", score)
		}
	}
}

func TestNewChecksSeedAndAffectDeviceSummary(t *testing.T) {
	pm := newTestManager(t)
	profile, err := pm.GetProfile("win-laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := profile.Queries["windows_antivirus"]; !ok {
		t.Fatal("database-backed profile missing antivirus check")
	}
	for category, rows := range map[string]string{
		"windows_antivirus": `[{"antivirus":"Poor"}]`,
		"secure_boot":       `[{"secure_boot":"1"}]`,
		"windows_firewall":  `[{"firewall":"Good"}]`,
		"windows_uac":       `[{"user_account_control":"Good"}]`,
	} {
		if err := pm.IngestResult("node-security", "env", QueryPrefix+category, []byte(rows)); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := pm.GetSummaryByNode("node-security")
	if err != nil || summary == nil || summary.RiskLevel != "high" {
		t.Fatalf("confirmed antivirus failure should escalate otherwise healthy node to high: %+v, %v", summary, err)
	}
	summaries, err := pm.GetSummaryByNodes([]string{"node-security"})
	if err != nil || summaries["NODE-SECURITY"] == nil || summaries["NODE-SECURITY"].RiskLevel != "high" {
		t.Fatalf("fleet and detail risk must agree: %+v, %v", summaries, err)
	}
	if err := pm.DB.Model(&PostureCheck{}).Where("scoring_rule = ?", "windows_antivirus").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := pm.SeedDefaultChecks(); err != nil {
		t.Fatal(err)
	}
	summary, err = pm.GetSummaryByNode("node-security")
	if err != nil || summary.RiskLevel != "low" {
		t.Fatalf("disabled check must stay disabled after reseeding: %+v, %v", summary, err)
	}
}
