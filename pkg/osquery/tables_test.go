package osquery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTablesKeepsQueryBuilderSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tables.json")
	data := `[{"name":"processes","description":"Running processes","url":"https://example.test/processes","platforms":["linux"],"columns":[{"name":"pid","description":"Process identifier","type":"bigint","required":true}]}]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write schema fixture: %v", err)
	}

	tables, err := LoadTables(path)
	if err != nil {
		t.Fatalf("LoadTables: %v", err)
	}
	if len(tables) != 1 || len(tables[0].Columns) != 1 {
		t.Fatalf("unexpected schema: %#v", tables)
	}
	if tables[0].Description != "Running processes" {
		t.Fatalf("description was not preserved: %q", tables[0].Description)
	}
	if tables[0].Columns[0].Name != "pid" || tables[0].Columns[0].Type != "bigint" {
		t.Fatalf("column metadata was not preserved: %#v", tables[0].Columns[0])
	}
	if tables[0].Filter != "filter-linux" {
		t.Fatalf("platform filter = %q, want filter-linux", tables[0].Filter)
	}
}
