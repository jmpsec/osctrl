package mcp

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/types"
)

// defaultTableLimit caps list_osquery_tables. The osquery schema runs to
// several hundred tables; the full list with descriptions is large enough
// that returning it unasked crowds out the actual investigation.
const defaultTableLimit = 100

// TableSummary is one row of list_osquery_tables — enough to pick a table,
// not enough to write a query. get_table_schema supplies the columns.
type TableSummary struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Platforms   []string `json:"platforms"`
	Evented     bool     `json:"evented"`
}

// TableColumn describes one column of an osquery table.
type TableColumn struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	// Required marks a column osquery will not scan without: a query that
	// omits it in the WHERE clause returns zero rows rather than an error.
	Required bool `json:"required"`
	Index    bool `json:"index"`
	Hidden   bool `json:"hidden"`
}

type listTablesIn struct {
	NameContains string `json:"name_contains,omitempty" jsonschema:"case-insensitive substring match on the table name"`
	Platform     string `json:"platform,omitempty" jsonschema:"only tables available on this platform: linux, darwin, or windows"`
	Limit        int    `json:"limit,omitempty" jsonschema:"maximum tables to return (default 100)"`
}

type listTablesOut struct {
	Tables    []TableSummary `json:"tables"`
	Matched   int            `json:"matched"`
	Returned  int            `json:"returned"`
	Truncated bool           `json:"truncated"`
}

type getTableSchemaIn struct {
	Name string `json:"name" jsonschema:"exact osquery table name, for example processes or launchd"`
}

type getTableSchemaOut struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Platforms   []string      `json:"platforms"`
	Evented     bool          `json:"evented"`
	Cacheable   bool          `json:"cacheable"`
	Notes       string        `json:"notes"`
	URL         string        `json:"url"`
	Columns     []TableColumn `json:"columns"`
}

func addSchemaTools(s *sdk.Server, b Backend) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "list_osquery_tables",
		Description: "List the osquery tables this osctrl deployment knows about, " +
			"filtered by name substring or platform. Use this to discover what is " +
			"queryable, then get_table_schema for the columns before writing SQL.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in listTablesIn) (*sdk.CallToolResult, listTablesOut, error) {
		all, err := b.GetOsqueryTables()
		if err != nil {
			return nil, listTablesOut{}, err
		}
		needle := strings.ToLower(strings.TrimSpace(in.NameContains))
		platform := strings.ToLower(strings.TrimSpace(in.Platform))
		matched := make([]types.OsqueryTable, 0, len(all))
		for _, t := range all {
			if needle != "" && !strings.Contains(strings.ToLower(t.Name), needle) {
				continue
			}
			if platform != "" && !hasPlatform(t.Platforms, platform) {
				continue
			}
			matched = append(matched, t)
		}

		limit := in.Limit
		if limit <= 0 {
			limit = defaultTableLimit
		}
		out := listTablesOut{Matched: len(matched)}
		if len(matched) > limit {
			out.Truncated = true
			matched = matched[:limit]
		}
		out.Tables = make([]TableSummary, 0, len(matched))
		for _, t := range matched {
			out.Tables = append(out.Tables, TableSummary{
				Name:        t.Name,
				Description: t.Description,
				Platforms:   t.Platforms,
				Evented:     t.Evented,
			})
		}
		out.Returned = len(out.Tables)
		return nil, out, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "get_table_schema",
		Description: "Columns and metadata for one osquery table. Read this before " +
			"writing osquery SQL: column names differ from other SQL dialects and " +
			"vary by platform, and columns marked required must appear in the WHERE " +
			"clause or the query silently returns no rows.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in getTableSchemaIn) (*sdk.CallToolResult, getTableSchemaOut, error) {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return nil, getTableSchemaOut{}, fmt.Errorf("name is required: an exact osquery table name")
		}
		all, err := b.GetOsqueryTables()
		if err != nil {
			return nil, getTableSchemaOut{}, err
		}
		for _, t := range all {
			if !strings.EqualFold(t.Name, name) {
				continue
			}
			out := getTableSchemaOut{
				Name:        t.Name,
				Description: t.Description,
				Platforms:   t.Platforms,
				Evented:     t.Evented,
				Cacheable:   t.Cacheable,
				Notes:       t.Notes,
				URL:         t.URL,
				Columns:     make([]TableColumn, 0, len(t.Columns)),
			}
			for _, c := range t.Columns {
				out.Columns = append(out.Columns, TableColumn{
					Name:        c.Name,
					Type:        c.Type,
					Description: c.Description,
					Required:    c.Required,
					Index:       c.Index,
					Hidden:      c.Hidden,
				})
			}
			return nil, out, nil
		}
		return nil, getTableSchemaOut{}, fmt.Errorf("no osquery table named %q; use list_osquery_tables to find the exact name", name)
	})
}

func hasPlatform(platforms []string, want string) bool {
	for _, p := range platforms {
		if strings.EqualFold(p, want) {
			return true
		}
	}
	return false
}
