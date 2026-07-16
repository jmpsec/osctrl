package posture

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestQueryPrefixDefaultsToOsctrlPosture(t *testing.T) {
	if QueryPrefix != DefaultQueryPrefix {
		t.Fatalf("unexpected posture query prefix %q", QueryPrefix)
	}
	if !IsPostureQuery("osctrl:posture:packages") {
		t.Fatal("default posture prefix was not recognized")
	}
}

func TestQueryPrefixCanBeConfigured(t *testing.T) {
	SetPrefix("custom:")
	t.Cleanup(func() { SetPrefix(DefaultQueryPrefix) })

	if !IsPostureQuery("custom:packages") {
		t.Fatal("custom posture prefix was not recognized")
	}
	if IsPostureQuery("osctrl:posture:packages") {
		t.Fatal("default posture prefix matched after custom prefix was configured")
	}
	if PostureCategory("custom:packages") != "packages" {
		t.Fatalf("unexpected custom posture category %q", PostureCategory("custom:packages"))
	}
}

func TestEmptyQueryPrefixDisablesPostureIngestion(t *testing.T) {
	SetPrefix("")
	t.Cleanup(func() { SetPrefix(DefaultQueryPrefix) })

	if IsPostureQuery("osctrl:posture:packages") {
		t.Fatal("empty posture prefix should disable posture query matching")
	}
}

func TestWindowsProfilesUseSupportedEncryptionTable(t *testing.T) {
	for _, profile := range []PostureProfile{WindowsServerProfile(), WindowsLaptopProfile()} {
		query, ok := profile.Queries["disk_encryption"]
		if !ok {
			t.Fatalf("%s has no disk encryption query", profile.ID)
		}
		if !strings.Contains(query.Query, "bitlocker_info") {
			t.Errorf("%s disk encryption query does not use bitlocker_info: %s", profile.ID, query.Query)
		}
	}
}

func TestWindowsProfilesDoNotUseDarwinWiFiTable(t *testing.T) {
	if _, ok := WindowsLaptopProfile().Queries["wifi_networks"]; ok {
		t.Fatal("Windows laptop profile includes the Darwin-only wifi_networks table")
	}
}

func TestWindowsServicesUseOsqueryStatusValue(t *testing.T) {
	query := WindowsServerProfile().Queries["windows_services"].Query
	if !strings.Contains(query, "status = 'RUNNING'") {
		t.Fatalf("Windows services query uses an unsupported status value: %s", query)
	}
}

func TestProfileTablesSupportTargetPlatform(t *testing.T) {
	type schemaTable struct {
		Name      string   `json:"name"`
		Platforms []string `json:"platforms"`
	}

	data, err := os.ReadFile("../../deploy/osquery/data/5.23.1.json")
	if err != nil {
		t.Fatalf("read bundled osquery schema: %v", err)
	}
	var schema []schemaTable
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse bundled osquery schema: %v", err)
	}
	tables := make(map[string][]string, len(schema))
	for _, table := range schema {
		tables[table.Name] = table.Platforms
	}

	tablePattern := regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+([a-z_]+)`)
	for _, profile := range AllProfiles() {
		for name, query := range profile.Queries {
			matches := tablePattern.FindAllStringSubmatch(query.Query, -1)
			if len(matches) == 0 {
				t.Errorf("%s/%s references no table", profile.ID, name)
				continue
			}
			for _, match := range matches {
				platforms, ok := tables[match[1]]
				if !ok {
					t.Errorf("%s/%s references unknown table %s", profile.ID, name, match[1])
					continue
				}
				if !slices.Contains(platforms, profile.Platform) {
					t.Errorf("%s/%s uses table %s on %s; supported platforms: %v", profile.ID, name, match[1], profile.Platform, platforms)
				}
			}
		}
	}
}
