package santa

import (
	"cmp"
	"slices"

	"gorm.io/gorm"
)

// RuleSpec is the portable form of a rule: what export writes and import reads.
type RuleSpec struct {
	Identifier string `json:"identifier"`
	RuleType   string `json:"rule_type"`
	Policy     string `json:"policy"`
	CELExpr    string `json:"cel_expr"`
	CustomMsg  string `json:"custom_msg"`
	CustomURL  string `json:"custom_url"`
	Scope      string `json:"scope"`
	ScopeValue string `json:"scope_value"`
}

// Spec returns the portable fields of r.
func (r Rule) Spec() RuleSpec {
	return RuleSpec{
		Identifier: r.Identifier, RuleType: r.RuleType, Policy: r.Policy, CELExpr: r.CELExpr,
		CustomMsg: r.CustomMsg, CustomURL: r.CustomURL, Scope: r.Scope, ScopeValue: r.ScopeValue,
	}
}

// ruleKey is what the unique index on santa_rules covers within an environment.
type ruleKey struct{ ruleType, identifier, scope, scopeValue string }

func (s RuleSpec) key() ruleKey { return ruleKey{s.RuleType, s.Identifier, s.Scope, s.ScopeValue} }

// ExportRules returns the rules as specs in a stable order (type, identifier,
// scope, scope value), so an export kept in git diffs cleanly.
func ExportRules(rules []Rule) []RuleSpec {
	out := make([]RuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Spec())
	}
	slices.SortFunc(out, func(a, b RuleSpec) int {
		return cmp.Or(cmp.Compare(a.RuleType, b.RuleType), cmp.Compare(a.Identifier, b.Identifier),
			cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.ScopeValue, b.ScopeValue))
	})
	return out
}

// ImportIssue is one imported rule that blocks the import.
type ImportIssue struct {
	// Position of the rule in the import, starting at 0
	Index  int      `json:"index"`
	Rule   RuleSpec `json:"rule"`
	Reason string   `json:"reason"`
}

// ImportResult reports what an import does, or would do on a dry run.
type ImportResult struct {
	// Rules that do not exist yet
	New int `json:"new"`
	// Rules identical to an existing rule or to an earlier rule in the import; skipped
	Duplicate int `json:"duplicate"`
	// Same type, identifier and scope as another rule, but different content
	Conflicts []ImportIssue `json:"conflicts"`
	// Rules that fail validation
	Invalid []ImportIssue `json:"invalid"`
	// True when the import was applied (also when there was nothing new to store);
	// false on a dry run and when conflicts or invalid rules blocked it
	Applied bool `json:"applied"`
}

// Blocked reports whether the import has rules that stop it from being applied.
func (r ImportResult) Blocked() bool { return len(r.Conflicts) > 0 || len(r.Invalid) > 0 }

// ImportRules classifies specs against the environment's rules and, when apply
// is set and nothing is invalid or conflicting, creates the new ones in one
// transaction. Existing rules are never modified.
func (m *Manager) ImportRules(envID uint, user string, specs []RuleSpec, apply bool) (ImportResult, error) {
	res := ImportResult{Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}}
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		var existing []Rule
		if err := tx.Where("environment_id = ?", envID).Find(&existing).Error; err != nil {
			return err
		}
		seen := make(map[ruleKey]RuleSpec, len(existing)+len(specs))
		for _, r := range existing {
			seen[r.Spec().key()] = r.Spec()
		}
		var create []Rule
		for i, s := range specs {
			r := Rule{
				EnvironmentID: envID, CreatedBy: user,
				Identifier: s.Identifier, RuleType: s.RuleType, Policy: s.Policy, CELExpr: s.CELExpr,
				CustomMsg: s.CustomMsg, CustomURL: s.CustomURL, Scope: s.Scope, ScopeValue: s.ScopeValue,
			}
			if err := ValidateRule(&r); err != nil {
				res.Invalid = append(res.Invalid, ImportIssue{Index: i, Rule: s, Reason: err.Error()})
				continue
			}
			norm := r.Spec()
			prev, ok := seen[norm.key()]
			switch {
			case !ok:
				seen[norm.key()] = norm
				create = append(create, r)
			case prev == norm:
				res.Duplicate++
			case prev.Policy != norm.Policy:
				res.Conflicts = append(res.Conflicts, ImportIssue{Index: i, Rule: s, Reason: "a rule with this type, identifier and scope already has policy " + prev.Policy})
			default:
				res.Conflicts = append(res.Conflicts, ImportIssue{Index: i, Rule: s, Reason: "a rule with this type, identifier and scope already exists with a different message, URL or CEL expression"})
			}
		}
		res.New = len(create)
		if !apply || res.Blocked() {
			return nil
		}
		res.Applied = true
		if len(create) == 0 {
			return nil
		}
		return tx.CreateInBatches(&create, 200).Error
	})
	return res, err
}
