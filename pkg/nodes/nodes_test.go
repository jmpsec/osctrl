package nodes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestSortableColumnsAllowlist verifies that every entry in SortableColumns
// maps to a non-empty database column name and that the SPA-critical keys
// resolve to the expected columns.
func TestSortableColumnsAllowlist(t *testing.T) {
	// Every key must map to a non-empty db column.
	for k, v := range SortableColumns {
		if v == "" {
			t.Errorf("SortableColumns[%q] is empty", k)
		}
	}

	// Spot-check the contract used by the SPA.
	cases := map[string]string{
		"uuid":      "uuid",
		"lastseen":  "last_seen",
		"firstseen": "created_at",
		"ip":        "ip_address",
		"hostname":  "hostname",
		"localname": "localname",
		"platform":  "platform",
		"version":   "platform_version",
		"osquery":   "osquery_version",
	}
	for k, want := range cases {
		got, ok := SortableColumns[k]
		if !ok {
			t.Errorf("SortableColumns missing expected key %q", k)
			continue
		}
		if got != want {
			t.Errorf("SortableColumns[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestSortableColumnsRejectsUnknown(t *testing.T) {
	if _, ok := SortableColumns["unknown_column"]; ok {
		t.Error("SortableColumns should not contain unknown_column")
	}
	if _, ok := SortableColumns[""]; ok {
		t.Error("SortableColumns should not contain the empty key")
	}
	if _, ok := SortableColumns["DROP TABLE"]; ok {
		t.Error("SortableColumns should not contain SQL fragments")
	}
}

// TestSafeOrderExpr verifies the deprecated GetByEnvPage / SearchByEnvPage
// callers can never inject SQL via orderBy — unknown / empty / malicious
// values all fall back to the safe default.
func TestSafeOrderExpr(t *testing.T) {
	cases := []struct {
		name    string
		orderBy string
		desc    bool
		want    string
	}{
		{"empty falls back", "", false, "last_seen DESC"},
		{"unknown column falls back", "DROP TABLE", true, "last_seen DESC"},
		{"injection attempt falls back", "1; SELECT 1", false, "last_seen DESC"},
		// uuid is in SortableColumns
		{"allowlisted asc", "uuid", false, "uuid ASC"},
		{"allowlisted desc", "uuid", true, "uuid DESC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeOrderExpr(tc.orderBy, tc.desc)
			if got != tc.want {
				t.Errorf("safeOrderExpr(%q, %v) = %q, want %q", tc.orderBy, tc.desc, got, tc.want)
			}
		})
	}
}

func TestGetByPlatformAllReturnsAllPlatformNodes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	manager := CreateNodes(db)
	now := time.Now()
	nodes := []OsqueryNode{
		{UUID: "NODE-1", Platform: "linux", EnvironmentID: 7, LastSeen: now},
		{UUID: "NODE-2", Platform: "windows", EnvironmentID: 7, LastSeen: now},
		{UUID: "NODE-3", Platform: "darwin", EnvironmentID: 99, LastSeen: now},
	}
	for _, node := range nodes {
		require.NoError(t, db.Create(&node).Error)
	}

	got, err := manager.GetByPlatform(7, AllNodes, ActiveNodes, 24)
	require.NoError(t, err)
	require.Len(t, got, 2)
}
