package posture

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// SQLite preparation checks selected columns, aliases and predicates against
// the bundled osquery schema, in addition to the platform checks in templates_test.
func TestSecurityQueriesMatchBundledSchema(t *testing.T) {
	var schema []struct {
		Name    string `json:"name"`
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
	}
	raw, err := os.ReadFile("../../deploy/osquery/data/5.23.1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	pm := newTestManager(t)
	db, err := pm.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, table := range schema {
		var columns []string
		for _, column := range table.Columns {
			columns = append(columns, `"`+column.Name+`" TEXT`)
		}
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS "` + table.Name + `" (` + strings.Join(columns, ",") + `)`); err != nil {
			t.Fatalf("create schema table %s: %v", table.Name, err)
		}
	}
	securityCategories := map[string]bool{}
	for _, rule := range securityRules() {
		for _, category := range rule.Categories {
			securityCategories[category] = true
		}
	}
	for _, profile := range AllProfiles() {
		for category, query := range profile.Queries {
			if !securityCategories[category] {
				continue
			}
			if !query.Snapshot || query.Interval != 86400 || query.Platform != profile.Platform {
				t.Errorf("%s/%s: invalid collection settings: %+v", profile.ID, category, query)
			}
			stmt, err := db.Prepare(query.Query)
			if err != nil {
				t.Errorf("%s/%s: query does not match osquery schema: %v", profile.ID, category, err)
				continue
			}
			_ = stmt.Close()
		}
	}
}

func TestSecurityChecksApplyToAppropriateProfiles(t *testing.T) {
	for _, profile := range AllProfiles() {
		if _, ok := profile.Queries["secure_boot"]; !ok {
			t.Errorf("%s lacks secure boot collection", profile.ID)
		}
		_, hasSecurityCenter := profile.Queries["windows_antivirus"]
		if hasSecurityCenter != (profile.ID == "win-laptop") {
			t.Errorf("%s has incorrect Security Center applicability", profile.ID)
		}
		if profile.ID == "win-server" {
			for _, query := range profile.Queries {
				if strings.Contains(query.Query, "windows_security_center") {
					t.Error("Windows Server must not query the unsupported Security Center API")
				}
			}
		}
		if profile.Platform == "linux" {
			for _, category := range []string{"selinux", "apparmor", "linux_aslr", "audit_service"} {
				if _, ok := profile.Queries[category]; !ok {
					t.Errorf("%s lacks %s", profile.ID, category)
				}
			}
		}
	}
	for _, check := range defaultChecks() {
		if err := validateCheck(check); err != nil {
			t.Errorf("invalid seeded check %s/%s: %v", check.ProfileID, check.Category, err)
		}
	}
}
