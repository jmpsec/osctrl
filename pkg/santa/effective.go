package santa

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

func scopeRank(r Rule) int {
	switch r.Scope {
	case "node":
		return 2
	case "tag":
		return 1
	}
	return 0
}

func ruleLess(a, b Rule) int {
	if c := strings.Compare(a.RuleType, b.RuleType); c != 0 {
		return c
	}
	return strings.Compare(a.Identifier, b.Identifier)
}

// EffectiveRules returns the rules applying to a node, one per (RuleType,
// Identifier), sorted by that key. The most specific scope wins (node > tag >
// env); ties go to the lowest ID.
func (m *Manager) EffectiveRules(envID uint, nodeUUID string, tags []string) ([]Rule, error) {
	all, err := m.Rules(envID)
	if err != nil {
		return nil, err
	}
	best := map[[2]string]Rule{}
	for _, r := range all {
		switch r.Scope {
		case "env":
		case "tag":
			if !slices.Contains(tags, r.ScopeValue) {
				continue
			}
		case "node":
			if !strings.EqualFold(r.ScopeValue, nodeUUID) {
				continue
			}
		default:
			continue
		}
		k := [2]string{r.RuleType, r.Identifier}
		if cur, ok := best[k]; !ok || scopeRank(r) > scopeRank(cur) || (scopeRank(r) == scopeRank(cur) && r.ID < cur.ID) {
			best[k] = r
		}
	}
	out := make([]Rule, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	slices.SortFunc(out, ruleLess)
	return out, nil
}

// RulesDigest is an order-independent sha256 hex digest of the rules' synced fields.
func RulesDigest(rules []Rule) string {
	sorted := slices.Clone(rules)
	slices.SortFunc(sorted, ruleLess)
	h := sha256.New()
	for _, r := range sorted {
		for _, f := range []string{r.RuleType, r.Identifier, r.Policy, r.CELExpr, r.CustomMsg, r.CustomURL} {
			fmt.Fprintf(h, "%d:%s", len(f), f)
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
