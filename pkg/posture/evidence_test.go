package posture

import (
	"errors"
	"testing"
)

func gradeRule() ScoringRule {
	return ScoringRule{
		RuleKey: "graded", Categories: []string{"graded"}, Title: "Graded", Severity: SeverityCritical,
		Grade: func(data map[string][]map[string]interface{}) (string, string, Severity) {
			level, _ := data["graded"][0]["level"].(string)
			switch level {
			case "high":
				return "fail", "a high finding", SeverityHigh
			case "none":
				return "pass", "clean", SeverityCritical
			}
			return "warn", "a medium finding", SeverityMedium
		},
	}
}

func gradedRecord(uuid, level string) NodePosture {
	return NodePosture{NodeUUID: uuid, Category: "graded", RowCount: 1, Summary: `[{"level":"` + level + `"}]`}
}

type fakeEvidence struct {
	records map[string][]NodePosture
	err     error
}

func (f *fakeEvidence) ScoringRules() []ScoringRule { return []ScoringRule{gradeRule()} }

func (f *fakeEvidence) ScoreEvidence(uuids []string) (map[string][]NodePosture, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]NodePosture{}
	for _, u := range uuids {
		if r, ok := f.records[u]; ok {
			out[u] = r
		}
	}
	return out, nil
}

// The evidence decides the severity, and the severity decides the weight.
func TestGradeSetsTheControlSeverityAndWeight(t *testing.T) {
	sc := &ScoreCalculator{rules: []ScoringRule{gradeRule()}}
	score := sc.Score([]NodePosture{gradedRecord("N1", "high")})
	if len(score.Controls) != 1 {
		t.Fatalf("controls = %+v", score.Controls)
	}
	c := score.Controls[0]
	if c.Status != "fail" || c.Severity != SeverityHigh || c.MaxScore != SeverityWeight[SeverityHigh] || c.Score != SeverityWeight[SeverityHigh] {
		t.Fatalf("graded control = %+v", c)
	}
	warn := sc.Score([]NodePosture{gradedRecord("N1", "medium")}).Controls[0]
	if warn.Status != "warn" || warn.MaxScore != SeverityWeight[SeverityMedium] || warn.Score != SeverityWeight[SeverityMedium]/warnDivisor {
		t.Fatalf("graded warn = %+v", warn)
	}
}

func TestScoreNodeAddsEvidenceForANodeWithoutPostureData(t *testing.T) {
	pm := newTestManager(t)
	pm.Evidence = &fakeEvidence{records: map[string][]NodePosture{"N1": {gradedRecord("N1", "high")}}}
	score, err := pm.ScoreNode("N1")
	if err != nil {
		t.Fatalf("ScoreNode: %v", err)
	}
	if len(score.Controls) != 1 || score.Controls[0].Category != "graded" || score.RiskLevel != "critical" {
		t.Fatalf("score = %+v", score)
	}
}

// No evidence for a node leaves its evidence rules unevaluated: the score is
// exactly what posture data alone gives.
func TestScoreNodeWithoutEvidenceMatchesPostureAlone(t *testing.T) {
	pm := newTestManager(t)
	if err := pm.DB.Create(&NodePosture{NodeUUID: "N1", Category: "patches", RowCount: 1, Summary: `[{"hotfix_id":"KB1"}]`}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := pm.ScoreNode("N1")
	if err != nil {
		t.Fatalf("ScoreNode: %v", err)
	}
	pm.Evidence = &fakeEvidence{records: map[string][]NodePosture{}}
	after, err := pm.ScoreNode("N1")
	if err != nil {
		t.Fatalf("ScoreNode: %v", err)
	}
	if before.TotalScore != after.TotalScore || len(before.Controls) != len(after.Controls) || before.RiskLevel != after.RiskLevel {
		t.Fatalf("evidence without a record changed the score: before %+v after %+v", before, after)
	}
}

func TestSummariesIncludeNodesWithOnlyEvidence(t *testing.T) {
	pm := newTestManager(t)
	pm.Evidence = &fakeEvidence{records: map[string][]NodePosture{"N1": {gradedRecord("N1", "high")}}}
	out, err := pm.GetSummaryByNodes([]string{"N1", "N2"})
	if err != nil {
		t.Fatalf("GetSummaryByNodes: %v", err)
	}
	if out["N1"] == nil || out["N1"].RiskLevel != "critical" {
		t.Fatalf("N1 summary = %+v", out["N1"])
	}
	if _, ok := out["N2"]; ok {
		t.Fatal("a node with neither posture data nor evidence has no summary")
	}
	single, err := pm.GetSummaryByNode("N1")
	if err != nil || single == nil || single.RiskLevel != "critical" {
		t.Fatalf("GetSummaryByNode = %+v, %v", single, err)
	}
	none, err := pm.GetSummaryByNode("N2")
	if err != nil || none != nil {
		t.Fatalf("GetSummaryByNode(N2) = %+v, %v", none, err)
	}
}

func TestEvidenceErrorsPropagate(t *testing.T) {
	pm := newTestManager(t)
	pm.Evidence = &fakeEvidence{err: errors.New("db down")}
	if _, err := pm.ScoreNode("N1"); err == nil {
		t.Fatal("an evidence error must not read as a clean score")
	}
}

// A posture query that writes the category the evidence owns must not be
// graded as evidence: only the evidence source speaks for its rules.
func TestPostureRecordsCannotImpersonateEvidence(t *testing.T) {
	pm := newTestManager(t)
	pm.Evidence = &fakeEvidence{records: map[string][]NodePosture{}}
	if err := pm.DB.Create(&NodePosture{NodeUUID: "N1", Category: "graded", RowCount: 1, Summary: `[{"level":"none"}]`}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	score, err := pm.ScoreNode("N1")
	if err != nil {
		t.Fatalf("ScoreNode: %v", err)
	}
	if len(score.Controls) != 0 {
		t.Fatalf("a posture record graded the evidence control: %+v", score.Controls)
	}
	out, err := pm.GetSummaryByNodes([]string{"N1"})
	if err != nil {
		t.Fatalf("GetSummaryByNodes: %v", err)
	}
	if _, ok := out["N1"]; ok {
		t.Fatalf("summary from an impersonating record: %+v", out["N1"])
	}
}
