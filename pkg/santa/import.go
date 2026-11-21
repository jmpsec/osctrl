package santa

import (
	"cmp"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

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
	// True when conflicts are skipped instead of blocking: the clean rules are
	// stored and the conflicts are listed, not imported
	ConflictsSkipped bool `json:"conflicts_skipped"`
}

// Blocked reports whether the import has rules that stop it from being applied.
func (r ImportResult) Blocked() bool {
	return len(r.Invalid) > 0 || (len(r.Conflicts) > 0 && !r.ConflictsSkipped)
}

// ImportRules classifies specs against the environment's rules and, when apply
// is set and nothing is invalid or conflicting, creates the new ones in one
// transaction. With skipConflicts, conflicts are left out instead of blocking.
// Existing rules are never modified.
func (m *Manager) ImportRules(envID uint, user string, specs []RuleSpec, apply, skipConflicts bool) (ImportResult, error) {
	res := ImportResult{Conflicts: []ImportIssue{}, Invalid: []ImportIssue{}, ConflictsSkipped: skipConflicts}
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

// ruleCSVColumns are the CSV columns of a rule export, in RuleSpec order.
var ruleCSVColumns = []string{"identifier", "rule_type", "policy", "cel_expr", "custom_msg", "custom_url", "scope", "scope_value"}

func (s RuleSpec) csvRow() []string {
	return []string{s.Identifier, s.RuleType, s.Policy, s.CELExpr, s.CustomMsg, s.CustomURL, s.Scope, s.ScopeValue}
}

// WriteRulesCSV writes specs as CSV with a header row. Cells that start like a
// spreadsheet formula are prefixed with a quote, which ReadRulesCSV removes.
func WriteRulesCSV(w io.Writer, specs []RuleSpec) error {
	cw := csv.NewWriter(w)
	_ = cw.Write(ruleCSVColumns)
	for _, s := range specs {
		row := s.csvRow()
		for i := range row {
			row[i] = csvCell(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	return cw.Error()
}

// ReadRulesCSV reads rules from CSV with a header row naming the columns, in
// any order; unknown columns are ignored and missing ones are empty.
func ReadRulesCSV(r io.Reader) ([]RuleSpec, error) {
	cr := csv.NewReader(r)
	header, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("empty CSV: expected a header row")
	}
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	for _, c := range []string{"identifier", "rule_type", "policy"} {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("CSV header is missing the %s column", c)
		}
	}
	specs := []RuleSpec{}
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return specs, nil
		}
		if err != nil {
			return nil, err
		}
		get := func(name string) string {
			i, ok := col[name]
			if !ok {
				return ""
			}
			return uncsvCell(row[i])
		}
		specs = append(specs, RuleSpec{
			Identifier: get("identifier"), RuleType: get("rule_type"), Policy: get("policy"), CELExpr: get("cel_expr"),
			CustomMsg: get("custom_msg"), CustomURL: get("custom_url"), Scope: get("scope"), ScopeValue: get("scope_value"),
		})
	}
}

// uncsvCell undoes csvCell.
func uncsvCell(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}
