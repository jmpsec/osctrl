package alerts

import "testing"

func TestVulnMatches(t *testing.T) {
	tests := []struct {
		min, severity string
		kev           bool
		want          bool
	}{
		{VulnMinKEV, "critical", false, false},
		{VulnMinKEV, "low", true, true},
		{VulnMinCritical, "critical", false, true},
		{VulnMinCritical, "high", false, false},
		{VulnMinCritical, "low", true, true}, // KEV outranks the CVSS score
		{VulnMinHigh, "high", false, true},
		{VulnMinHigh, "medium", false, false},
		{VulnMinMedium, "medium", false, true},
		{VulnMinLow, "low", false, true},
		{VulnMinLow, "unknown", false, false}, // unknown ranks below low
		{VulnMinAny, "unknown", false, true},
		{VulnMinAny, "low", false, true},
		{"bogus", "critical", false, false},
	}
	for _, tt := range tests {
		if got := vulnMatches(tt.min, tt.severity, tt.kev); got != tt.want {
			t.Errorf("vulnMatches(%q, %q, kev=%v) = %v, want %v", tt.min, tt.severity, tt.kev, got, tt.want)
		}
	}
}

func TestValidateVulnRule(t *testing.T) {
	ok := AlertRule{Name: "kev", Source: SourceVulnFinding, VulnMinSeverity: VulnMinKEV}
	if err := ValidateRule(ok); err != nil {
		t.Fatalf("a vulnerability rule needs no pattern: %v", err)
	}
	// Scripts send odd casing and spacing; accept and normalize it.
	if err := ValidateRule(AlertRule{Name: "x", Source: SourceVulnFinding, VulnMinSeverity: " High "}); err != nil {
		t.Fatalf("threshold should be case- and space-insensitive: %v", err)
	}
	for _, bad := range []string{"", "severe"} {
		err := ValidateRule(AlertRule{Name: "x", Source: SourceVulnFinding, VulnMinSeverity: bad})
		if err == nil {
			t.Fatalf("threshold %q must be rejected", bad)
		}
	}
}

func TestVulnRuleRoundTripAndSnapshot(t *testing.T) {
	m := newTestManager(t)
	created, err := m.CreateRule(AlertRule{Name: "kev", Source: SourceVulnFinding, VulnMinSeverity: " KEV ", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.VulnMinSeverity != VulnMinKEV {
		t.Fatalf("stored threshold = %q, want normalized %q", created.VulnMinSeverity, VulnMinKEV)
	}
	updated, err := m.UpdateRule(created.ID, AlertRule{Name: "kev", Source: SourceVulnFinding, VulnMinSeverity: "High", Enabled: true})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.VulnMinSeverity != VulnMinHigh {
		t.Fatalf("update must persist the threshold, got %q", updated.VulnMinSeverity)
	}
	store := NewStore()
	if err := m.LoadSnapshot(store); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	rs := store.Snapshot()
	if len(rs.vulnFinding) != 1 || rs.vulnFinding[0].vulnMin != VulnMinHigh {
		t.Fatalf("snapshot must carry the rule in the vulnerability bucket: %+v", rs.vulnFinding)
	}
	if rs.empty() {
		t.Fatal("a snapshot with only a vulnerability rule is not empty")
	}
}

// Rules that match no text ignore pattern fields: a stray match_type on a
// vulnerability or node-state rule must not keep it from loading.
func TestNonPatternRulesIgnorePatternFields(t *testing.T) {
	m := newTestManager(t)
	for _, src := range []string{SourceVulnFinding, SourceNodeInactive} {
		if _, err := m.CreateRule(AlertRule{Name: src, Source: src, VulnMinSeverity: VulnMinKEV,
			MatchType: "Substring", MatchValue: "x", Enabled: true}); err != nil {
			t.Fatalf("create %s: %v", src, err)
		}
	}
	store := NewStore()
	if err := m.LoadSnapshot(store); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	rs := store.Snapshot()
	if len(rs.vulnFinding) != 1 || len(rs.nodeInactive) != 1 {
		t.Fatalf("stored rules must load: vuln=%d inactive=%d", len(rs.vulnFinding), len(rs.nodeInactive))
	}
}
