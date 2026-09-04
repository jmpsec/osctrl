package mcp

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
)

const (
	// defaultQueryExpirationHours bounds every query this server schedules.
	//
	// osctrl treats ExpHours == 0 as "never expires", which is the wrong
	// default for an agent: an unbounded query keeps being handed to nodes
	// that enroll long after the investigation ended. Every query scheduled
	// here gets an explicit expiry.
	defaultQueryExpirationHours = 24
	// maxQueryExpirationHours caps how long an agent-scheduled query can
	// linger. A week is longer than any interactive investigation and short
	// enough that a forgotten query ages out on its own.
	maxQueryExpirationHours = 168
)

type runQueryIn struct {
	Environment string `json:"environment" jsonschema:"environment name, from list_environments"`
	Query       string `json:"query" jsonschema:"osquery SQL to run; check get_table_schema first"`
	// Target selectors. At least one is required unless AllNodes is set.
	UUIDs     []string `json:"uuids,omitempty" jsonschema:"target these node UUIDs"`
	Hostnames []string `json:"hostnames,omitempty" jsonschema:"target these hostnames"`
	Platforms []string `json:"platforms,omitempty" jsonschema:"target whole platforms: linux, darwin, or windows"`
	Tags      []string `json:"tags,omitempty" jsonschema:"target nodes carrying these tags"`
	AllNodes  bool     `json:"all_nodes,omitempty" jsonschema:"target every node in the environment; required to be explicit because it puts load on the whole fleet"`

	ExpirationHours int `json:"expiration_hours,omitempty" jsonschema:"hours before the query stops being handed to nodes (default 24, maximum 168)"`
}

type runQueryOut struct {
	Name     string `json:"name"`
	Guidance string `json:"guidance"`
}

type queryActionIn struct {
	Environment string `json:"environment" jsonschema:"environment name, from list_environments"`
	Name        string `json:"name" jsonschema:"query name, as returned by run_query or list_queries"`
}

type queryActionOut struct {
	Message string `json:"message"`
}

type tagNodeIn struct {
	Environment string `json:"environment" jsonschema:"environment name, from list_environments"`
	Identifier  string `json:"identifier" jsonschema:"node UUID, from search_nodes or get_node"`
	Tag         string `json:"tag" jsonschema:"tag name to apply; the tag must already exist in the environment"`
}

type tagNodeOut struct {
	Message string `json:"message"`
}

func addWriteTools(s *sdk.Server, b WriteBackend) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "run_query",
		Description: "Schedule an osquery SQL query against nodes in an environment. " +
			"This does real work on real machines: target as narrowly as the task " +
			"allows. " +
			"Check get_table_schema before writing SQL — osquery's columns differ " +
			"from other SQL dialects and vary by platform. " +
			"Returns a query name, not results: nodes answer asynchronously as they " +
			"check in, so poll get_query_results afterwards. " +
			"Requires query-level permission on the environment.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in runQueryIn) (*sdk.CallToolResult, runQueryOut, error) {
		if strings.TrimSpace(in.Environment) == "" {
			return nil, runQueryOut{}, fmt.Errorf("environment is required; call list_environments first")
		}
		query := strings.TrimSpace(in.Query)
		if query == "" {
			return nil, runQueryOut{}, fmt.Errorf("query is required")
		}
		// Carve queries pull files off endpoints. osctrl gates them behind
		// CarveLevel server-side, but file exfiltration is not a capability
		// this server hands to an agent at all — an operator who wants a
		// carve can run it from the SPA or osctrl-cli.
		if queries.IsCarveQuery(query) {
			return nil, runQueryOut{}, fmt.Errorf("carve queries are not available through MCP: they copy files off endpoints; run the carve from the SPA or osctrl-cli instead")
		}

		targeted := len(in.UUIDs) > 0 || len(in.Hostnames) > 0 || len(in.Platforms) > 0 || len(in.Tags) > 0
		if !targeted && !in.AllNodes {
			// osctrl reads "no selectors" as "the whole environment". Making
			// the model say so explicitly keeps a fleet-wide query from being
			// the result of an omitted argument.
			return nil, runQueryOut{}, fmt.Errorf("no target given: set uuids, hostnames, platforms, or tags — or set all_nodes to true to deliberately target the whole environment")
		}
		if targeted && in.AllNodes {
			return nil, runQueryOut{}, fmt.Errorf("all_nodes cannot be combined with specific targets; pick one")
		}

		exp := in.ExpirationHours
		if exp <= 0 {
			exp = defaultQueryExpirationHours
		}
		if exp > maxQueryExpirationHours {
			return nil, runQueryOut{}, fmt.Errorf("expiration_hours %d exceeds the maximum of %d", in.ExpirationHours, maxQueryExpirationHours)
		}

		// hidden=false always: an operator must be able to see what an agent
		// scheduled. Hidden queries exist for osctrl's own internal use, not
		// to keep agent activity out of the UI.
		res, err := b.RunQuery(in.Environment, query, in.UUIDs, in.Hostnames, in.Platforms, in.Tags, false, exp)
		if err != nil {
			return nil, runQueryOut{}, err
		}
		return nil, runQueryOut{
			Name: res.Name,
			Guidance: fmt.Sprintf(
				"Query %s scheduled, expiring in %dh. Nodes answer as they check in — "+
					"call get_query_results with this name, and compare total_items across "+
					"reads rather than treating the first page as final.", res.Name, exp),
		}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "expire_query",
		Description: "Stop a query from being handed to any more nodes. Results " +
			"already collected stay readable. Use this to cut short a query that " +
			"was too broad or is no longer needed.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in queryActionIn) (*sdk.CallToolResult, queryActionOut, error) {
		if err := validateQueryAction(in); err != nil {
			return nil, queryActionOut{}, err
		}
		res, err := b.ExpireQuery(in.Environment, in.Name)
		if err != nil {
			return nil, queryActionOut{}, err
		}
		return nil, queryActionOut{Message: res.Message}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "complete_query",
		Description: "Mark a query complete, so osctrl stops waiting on nodes that " +
			"have not answered. Results already collected stay readable.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in queryActionIn) (*sdk.CallToolResult, queryActionOut, error) {
		if err := validateQueryAction(in); err != nil {
			return nil, queryActionOut{}, err
		}
		res, err := b.CompleteQuery(in.Environment, in.Name)
		if err != nil {
			return nil, queryActionOut{}, err
		}
		return nil, queryActionOut{Message: res.Message}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "tag_node",
		Description: "Apply an existing tag to a node. Tags drive query targeting, " +
			"so adding one changes which queries a node will receive in future. " +
			"Requires admin permission on the environment.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in tagNodeIn) (*sdk.CallToolResult, tagNodeOut, error) {
		if strings.TrimSpace(in.Environment) == "" {
			return nil, tagNodeOut{}, fmt.Errorf("environment is required; call list_environments first")
		}
		if strings.TrimSpace(in.Identifier) == "" {
			return nil, tagNodeOut{}, fmt.Errorf("identifier is required: a node UUID")
		}
		if strings.TrimSpace(in.Tag) == "" {
			return nil, tagNodeOut{}, fmt.Errorf("tag is required")
		}
		// TagTypeCustom is the type for operator-applied tags; the others are
		// osctrl's own derived tags (environment, platform) and must not be
		// forged from here.
		if err := b.TagNode(in.Environment, in.Identifier, in.Tag, tags.TagTypeCustom, ""); err != nil {
			return nil, tagNodeOut{}, err
		}
		return nil, tagNodeOut{Message: fmt.Sprintf("tag %q applied to %s", in.Tag, in.Identifier)}, nil
	})
}

func validateQueryAction(in queryActionIn) error {
	if strings.TrimSpace(in.Environment) == "" {
		return fmt.Errorf("environment is required; call list_environments first")
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("name is required; use list_queries to find it")
	}
	return nil
}
