package console_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/stretchr/testify/require"
)

// osquery rejects the whole priming statement when one column is unknown, so
// every column must exist in the bundled osquery schema.
func TestPrimingSQLMatchesOsquerySchema(t *testing.T) {
	data, err := os.ReadFile("../../deploy/osquery/data/5.24.1.json")
	require.NoError(t, err)
	var schema []struct {
		Name    string `json:"name"`
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
	}
	require.NoError(t, json.Unmarshal(data, &schema))
	tables := map[string][]string{}
	for _, s := range schema {
		for _, c := range s.Columns {
			tables[s.Name] = append(tables[s.Name], c.Name)
		}
	}

	stmt := regexp.MustCompile(`^select (.+) from ([a-z_]+)$`)
	for name, sql := range map[string]string{"console": console.PrimingMetadataSQL, "fileexplorer": fileexplorer.PrimingMetadataSQL} {
		m := stmt.FindStringSubmatch(sql)
		require.NotNil(t, m, name)
		known, ok := tables[m[2]]
		require.True(t, ok, "%s: unknown table %s", name, m[2])
		for _, col := range strings.Split(m[1], ",") {
			require.Contains(t, known, strings.TrimSpace(col), "%s: unknown column in %s", name, m[2])
		}
	}
}
