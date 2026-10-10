package vulns

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type schemaTable struct {
	Name      string   `json:"name"`
	Platforms []string `json:"platforms"`
	Columns   []struct {
		Name string `json:"name"`
	} `json:"columns"`
}

func bundledSchema(t *testing.T) []schemaTable {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/osquery/data/5.23.1.json")
	require.NoError(t, err)
	var schema []schemaTable
	require.NoError(t, json.Unmarshal(raw, &schema))
	return schema
}

// Every query must prepare against the bundled osquery schema, so a typo in
// a column name fails here rather than silently on every node.
func TestProfileQueriesMatchBundledSchema(t *testing.T) {
	db := newTestDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	tables := map[string][]string{}
	for _, table := range bundledSchema(t) {
		tables[table.Name] = table.Platforms
		var cols []string
		for _, c := range table.Columns {
			cols = append(cols, `"`+c.Name+`" TEXT`)
		}
		_, err := sqlDB.Exec(`CREATE TABLE IF NOT EXISTS "` + table.Name + `" (` + strings.Join(cols, ",") + `)`)
		require.NoError(t, err, table.Name)
	}
	from := regexp.MustCompile(`(?i)\bFROM\s+([a-z_]+)`)
	for _, p := range Profiles() {
		for category, q := range p.Queries {
			stmt, err := sqlDB.Prepare(q.Query)
			if assert.NoError(t, err, "%s/%s", p.ID, category) {
				_ = stmt.Close()
			}
			m := from.FindStringSubmatch(q.Query)
			require.NotNil(t, m, "%s/%s", p.ID, category)
			assert.True(t, slices.Contains(tables[m[1]], p.Platform), "%s/%s: %s is not available on %s", p.ID, category, m[1], p.Platform)
			assert.Equal(t, QueryPrefix+category, q.QueryName)
			assert.True(t, q.Snapshot, "inventory must be a full snapshot: %s/%s", p.ID, category)
			assert.Equal(t, 86400, q.Interval)
		}
	}
}

func TestEveryProfileCollectsTheOS(t *testing.T) {
	for _, p := range Profiles() {
		assert.Contains(t, p.Queries, CategoryOS, p.ID)
	}
	linux, ok := Profile("vuln-linux")
	require.True(t, ok)
	assert.Contains(t, linux.Queries[CategoryDeb].Query, "install ok installed", "removed packages keep config files and must not count")
}
