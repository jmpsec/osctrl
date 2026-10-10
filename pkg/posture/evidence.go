package posture

import "slices"

// evidence.go — score evidence that posture queries do not collect.

// EvidenceSource contributes scoring rules and per-node evidence from
// another subsystem (vulnerability findings, from pkg/vulns). Its records
// use the NodePosture shape the calculator reads. A node it returns no
// record for leaves its rules unevaluated, exactly like an uncollected
// posture category.
type EvidenceSource interface {
	ScoringRules() []ScoringRule
	ScoreEvidence(nodeUUIDs []string) (map[string][]NodePosture, error)
}

// calculator is the calculator for the enabled checks plus the evidence
// source's rules.
func (pm *PostureManager) calculator() (*ScoreCalculator, error) {
	checks, err := pm.enabledChecks()
	if err != nil {
		return nil, err
	}
	sc := NewScoreCalculatorWithChecks(checks)
	if pm.Evidence != nil {
		sc.rules = append(sc.rules, pm.Evidence.ScoringRules()...)
	}
	return sc, nil
}

// evidenceFor returns evidence records per node; nil without a source.
func (pm *PostureManager) evidenceFor(nodeUUIDs []string) (map[string][]NodePosture, error) {
	if pm.Evidence == nil || len(nodeUUIDs) == 0 {
		return nil, nil
	}
	return pm.Evidence.ScoreEvidence(nodeUUIDs)
}

// evidenceOwned is the set of categories the evidence source's rules read.
// Posture records in them are dropped: a posture query must not grade, or
// pass, an evidence control.
func (pm *PostureManager) evidenceOwned() map[string]bool {
	if pm.Evidence == nil {
		return nil
	}
	owned := map[string]bool{}
	for _, r := range pm.Evidence.ScoringRules() {
		for _, c := range r.Categories {
			owned[c] = true
		}
	}
	return owned
}

// nodeRecords is a node's posture records plus its evidence.
func (pm *PostureManager) nodeRecords(nodeUUID string) ([]NodePosture, error) {
	records, err := pm.GetByNode(nodeUUID)
	if err != nil {
		return nil, err
	}
	owned := pm.evidenceOwned()
	records = slices.DeleteFunc(records, func(r NodePosture) bool { return owned[r.Category] })
	extra, err := pm.evidenceFor([]string{nodeUUID})
	if err != nil {
		return nil, err
	}
	return append(records, extra[nodeUUID]...), nil
}

// ScoreNode scores one node from its posture records and any evidence.
func (pm *PostureManager) ScoreNode(nodeUUID string) (PostureScore, error) {
	records, err := pm.nodeRecords(nodeUUID)
	if err != nil {
		return PostureScore{}, err
	}
	sc, err := pm.calculator()
	if err != nil {
		return PostureScore{}, err
	}
	return sc.Score(records), nil
}
