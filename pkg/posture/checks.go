package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// PostureCheck is an admin-editable posture scheduled-query template.
// ScoringRule selects a built-in evaluator; no executable logic is stored.
type PostureCheck struct {
	ID                 uint      `gorm:"primarykey" json:"id"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	ProfileID          string    `gorm:"type:varchar(64);uniqueIndex:idx_posture_check_profile_category" json:"profile_id"`
	ProfileName        string    `gorm:"type:varchar(255)" json:"profile_name"`
	ProfileDescription string    `gorm:"type:text" json:"profile_description"`
	ProfilePlatform    string    `gorm:"type:varchar(64)" json:"profile_platform"`
	Category           string    `gorm:"type:varchar(64);uniqueIndex:idx_posture_check_profile_category;index" json:"category"`
	Name               string    `gorm:"type:varchar(255)" json:"name"`
	Description        string    `gorm:"type:text" json:"description"`
	QueryName          string    `gorm:"type:varchar(255)" json:"query_name"`
	Query              string    `gorm:"type:text" json:"query"`
	Interval           int       `json:"interval"`
	Platform           string    `gorm:"type:varchar(64)" json:"platform"`
	Snapshot           bool      `json:"snapshot"`
	Enabled            bool      `gorm:"index" json:"enabled"`
	ScoringRule        string    `gorm:"type:varchar(64);index" json:"scoring_rule"`
	ControlID          string    `gorm:"type:varchar(64)" json:"control_id"`
	Framework          Framework `gorm:"type:varchar(32)" json:"framework"`
	Severity           Severity  `gorm:"type:varchar(32)" json:"severity"`
	Weight             int       `json:"weight"`
}

func (PostureCheck) TableName() string { return "posture_checks" }

// CheckPatch is the small PATCH/POST body used by the API. Pointer fields let
// PATCH distinguish "unset" from zero values.
type CheckPatch struct {
	ProfileID          *string `json:"profile_id,omitempty"`
	ProfileName        *string `json:"profile_name,omitempty"`
	ProfileDescription *string `json:"profile_description,omitempty"`
	ProfilePlatform    *string `json:"profile_platform,omitempty"`
	Category           *string `json:"category,omitempty"`
	Name               *string `json:"name,omitempty"`
	Description        *string `json:"description,omitempty"`
	QueryName          *string `json:"query_name,omitempty"`
	Query              *string `json:"query,omitempty"`
	Interval           *int    `json:"interval,omitempty"`
	Platform           *string `json:"platform,omitempty"`
	Snapshot           *bool   `json:"snapshot,omitempty"`
	Enabled            *bool   `json:"enabled,omitempty"`
	ScoringRule        *string `json:"scoring_rule,omitempty"`
	ControlID          *string `json:"control_id,omitempty"`
	Framework          *string `json:"framework,omitempty"`
	Severity           *string `json:"severity,omitempty"`
	Weight             *int    `json:"weight,omitempty"`
}

func migratePostureChecks(db *gorm.DB) error {
	return db.AutoMigrate(&PostureCheck{})
}

func (pm *PostureManager) SeedDefaultChecks() error {
	for _, check := range defaultChecks() {
		if err := pm.DB.Where("profile_id = ? AND category = ?", check.ProfileID, check.Category).
			Attrs(check).
			FirstOrCreate(&PostureCheck{}).Error; err != nil {
			return fmt.Errorf("seed posture check %s/%s: %w", check.ProfileID, check.Category, err)
		}
	}
	return nil
}

func (pm *PostureManager) ListChecks() ([]PostureCheck, error) {
	var checks []PostureCheck
	err := pm.DB.Order("profile_name ASC, category ASC, id ASC").Find(&checks).Error
	return checks, err
}

func (pm *PostureManager) GetCheck(id uint) (*PostureCheck, error) {
	var check PostureCheck
	if err := pm.DB.First(&check, id).Error; err != nil {
		return nil, err
	}
	return &check, nil
}

func (pm *PostureManager) CreateCheck(patch CheckPatch) (*PostureCheck, error) {
	check := PostureCheck{Enabled: true, Snapshot: true, Interval: 86400}
	applyCheckPatch(&check, patch)
	if err := validateCheck(check); err != nil {
		return nil, err
	}
	if err := pm.DB.Create(&check).Error; err != nil {
		return nil, err
	}
	return &check, nil
}

func (pm *PostureManager) UpdateCheck(id uint, patch CheckPatch) (*PostureCheck, error) {
	check, err := pm.GetCheck(id)
	if err != nil {
		return nil, err
	}
	applyCheckPatch(check, patch)
	if err := validateCheck(*check); err != nil {
		return nil, err
	}
	if err := pm.DB.Save(check).Error; err != nil {
		return nil, err
	}
	return check, nil
}

func (pm *PostureManager) DeleteCheck(id uint) error {
	return pm.DB.Delete(&PostureCheck{}, id).Error
}

func (pm *PostureManager) AllProfiles() ([]PostureProfile, error) {
	var checks []PostureCheck
	if err := pm.DB.Where("enabled = ?", true).Order("profile_name ASC, category ASC").Find(&checks).Error; err != nil {
		return nil, err
	}
	profiles := map[string]*PostureProfile{}
	for _, check := range checks {
		profile := profiles[check.ProfileID]
		if profile == nil {
			profile = &PostureProfile{
				ID:          check.ProfileID,
				Name:        check.ProfileName,
				Description: check.ProfileDescription,
				Platform:    check.ProfilePlatform,
				Queries:     map[string]ProfileQuery{},
			}
			profiles[check.ProfileID] = profile
		}
		profile.Queries[check.Category] = ProfileQuery{
			QueryName: check.QueryName,
			Query:     check.Query,
			Interval:  check.Interval,
			Platform:  check.Platform,
			Snapshot:  check.Snapshot,
		}
	}
	out := make([]PostureProfile, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, *profile)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (pm *PostureManager) GetProfile(id string) (*PostureProfile, error) {
	profiles, err := pm.AllProfiles()
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if profile.ID == id {
			return &profile, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (pm *PostureManager) enabledChecks() ([]PostureCheck, error) {
	var checks []PostureCheck
	err := pm.DB.Where("enabled = ?", true).Order("scoring_rule ASC, category ASC, profile_id ASC").Find(&checks).Error
	return checks, err
}

func (pm *PostureManager) Score(records []NodePosture) (PostureScore, error) {
	checks, err := pm.enabledChecks()
	if err != nil {
		return PostureScore{}, err
	}
	return NewScoreCalculatorWithChecks(checks).Score(records), nil
}

func defaultChecks() []PostureCheck {
	ruleByCategory := defaultRuleByCategory()
	var checks []PostureCheck
	for _, profile := range builtinProfiles() {
		for category, query := range profile.Queries {
			rule := ruleByCategory[category]
			check := PostureCheck{
				ProfileID:          profile.ID,
				ProfileName:        profile.Name,
				ProfileDescription: profile.Description,
				ProfilePlatform:    profile.Platform,
				Category:           category,
				Name:               strings.TrimSpace(rule.Title),
				Description:        strings.TrimSpace(rule.Description),
				QueryName:          QueryPrefix + category,
				Query:              query.Query,
				Interval:           query.Interval,
				Platform:           query.Platform,
				Snapshot:           query.Snapshot,
				Enabled:            true,
				ScoringRule:        rule.RuleKey,
				ControlID:          rule.ControlID,
				Framework:          rule.Framework,
				Severity:           rule.Severity,
				Weight:             ruleWeight(rule),
			}
			if check.Name == "" {
				check.Name = category
			}
			if check.Description == "" {
				check.Description = profile.Description
			}
			checks = append(checks, check)
		}
	}
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].ProfileID == checks[j].ProfileID {
			return checks[i].Category < checks[j].Category
		}
		return checks[i].ProfileID < checks[j].ProfileID
	})
	return checks
}

func defaultRuleByCategory() map[string]ScoringRule {
	out := map[string]ScoringRule{}
	for _, rule := range defaultRules() {
		for _, category := range rule.Categories {
			out[category] = rule
		}
	}
	return out
}

func applyCheckPatch(check *PostureCheck, patch CheckPatch) {
	if patch.ProfileID != nil {
		check.ProfileID = strings.TrimSpace(*patch.ProfileID)
	}
	if patch.ProfileName != nil {
		check.ProfileName = strings.TrimSpace(*patch.ProfileName)
	}
	if patch.ProfileDescription != nil {
		check.ProfileDescription = strings.TrimSpace(*patch.ProfileDescription)
	}
	if patch.ProfilePlatform != nil {
		check.ProfilePlatform = strings.TrimSpace(*patch.ProfilePlatform)
	}
	if patch.Category != nil {
		check.Category = strings.TrimSpace(*patch.Category)
	}
	if patch.Name != nil {
		check.Name = strings.TrimSpace(*patch.Name)
	}
	if patch.Description != nil {
		check.Description = strings.TrimSpace(*patch.Description)
	}
	if patch.QueryName != nil {
		check.QueryName = strings.TrimSpace(*patch.QueryName)
	}
	if patch.Query != nil {
		check.Query = strings.TrimSpace(*patch.Query)
	}
	if patch.Interval != nil {
		check.Interval = *patch.Interval
	}
	if patch.Platform != nil {
		check.Platform = strings.TrimSpace(*patch.Platform)
	}
	if patch.Snapshot != nil {
		check.Snapshot = *patch.Snapshot
	}
	if patch.Enabled != nil {
		check.Enabled = *patch.Enabled
	}
	if patch.ScoringRule != nil {
		check.ScoringRule = strings.TrimSpace(*patch.ScoringRule)
	}
	if patch.ControlID != nil {
		check.ControlID = strings.TrimSpace(*patch.ControlID)
	}
	if patch.Framework != nil {
		check.Framework = Framework(strings.TrimSpace(*patch.Framework))
	}
	if patch.Severity != nil {
		check.Severity = Severity(strings.TrimSpace(*patch.Severity))
	}
	if patch.Weight != nil {
		check.Weight = *patch.Weight
	}
}

func validateCheck(check PostureCheck) error {
	switch {
	case check.ProfileID == "":
		return fmt.Errorf("profile_id is required")
	case check.ProfileName == "":
		return fmt.Errorf("profile_name is required")
	case check.Category == "":
		return fmt.Errorf("category is required")
	case check.Name == "":
		return fmt.Errorf("name is required")
	case check.QueryName == "":
		return fmt.Errorf("query_name is required")
	case check.Query == "":
		return fmt.Errorf("query is required")
	case check.Interval < 0:
		return fmt.Errorf("interval must be zero or greater")
	case check.Weight < 0:
		return fmt.Errorf("weight must be zero or greater")
	}
	if check.Severity != "" {
		if _, ok := SeverityWeight[check.Severity]; !ok {
			return fmt.Errorf("invalid severity %q", check.Severity)
		}
	}
	if check.Framework != "" && check.Framework != FrameworkSOC2 && check.Framework != FrameworkISO27001 {
		return fmt.Errorf("invalid framework %q", check.Framework)
	}
	if check.ScoringRule != "" && !knownScoringRules()[check.ScoringRule] {
		return fmt.Errorf("unknown scoring_rule %q", check.ScoringRule)
	}
	return nil
}

func knownScoringRules() map[string]bool {
	out := map[string]bool{}
	for _, rule := range defaultRules() {
		if rule.RuleKey != "" {
			out[rule.RuleKey] = true
		}
	}
	return out
}
