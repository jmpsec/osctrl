package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/apiclient"
)

// EnvironmentSummary is the projection of environments.TLSEnvironment that
// tools return.
//
// The projection is a security boundary, not a formatting nicety:
// TLSEnvironment carries Secret, EnrollSecretPath, RemoveSecretPath and
// Certificate. Returning the struct as-is would put live enrollment secrets
// into an LLM context window — and, from there, into whatever transcript
// store the client keeps. Add fields here deliberately.
type EnvironmentSummary struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
}

type listEnvironmentsIn struct{}

type listEnvironmentsOut struct {
	Environments []EnvironmentSummary `json:"environments"`
}

type fleetStatsIn struct{}

// EnvironmentStats is the per-environment row of fleet_stats.
type EnvironmentStats struct {
	InactiveHours int64  `json:"inactive_hours"`
	Name          string `json:"name"`
	TotalNodes    int64  `json:"total_nodes"`
	ActiveNodes   int64  `json:"active_nodes"`
	InactiveNodes int64  `json:"inactive_nodes"`
	Linux         int64  `json:"linux"`
	Darwin        int64  `json:"darwin"`
	Windows       int64  `json:"windows"`
	Other         int64  `json:"other"`
}

type fleetStatsOut struct {
	TotalNodes    int64 `json:"total_nodes"`
	ActiveNodes   int64 `json:"active_nodes"`
	InactiveNodes int64 `json:"inactive_nodes"`
	// InactiveHours is the global default only; counts use per-environment thresholds.
	InactiveHours      int64              `json:"inactive_hours"`
	TotalActiveQueries int                `json:"total_active_queries"`
	TotalActiveCarves  int                `json:"total_active_carves"`
	Environments       []EnvironmentStats `json:"environments"`
}

func addFleetTools(s *sdk.Server, b Backend) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "list_environments",
		Description: "List the osctrl environments this token can see. " +
			"Most other tools take an environment name, so call this first. " +
			"Enrollment secrets and certificates are deliberately not returned.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ listEnvironmentsIn) (*sdk.CallToolResult, listEnvironmentsOut, error) {
		envs, err := b.GetEnvironments()
		if err != nil {
			return nil, listEnvironmentsOut{}, err
		}
		out := listEnvironmentsOut{Environments: make([]EnvironmentSummary, 0, len(envs))}
		for _, e := range envs {
			out.Environments = append(out.Environments, EnvironmentSummary{
				UUID:     e.UUID,
				Name:     e.Name,
				Hostname: e.Hostname,
				Type:     e.Type,
			})
		}
		return nil, out, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "fleet_stats",
		Description: "Fleet-wide node counts: totals, active vs inactive, and a " +
			"per-platform and per-environment breakdown. A node counts as inactive " +
			"once it has not checked in for that environment's inactive_hours. " +
			"Top-level inactive_hours is the global default; environment overrides apply to counts. Use this for " +
			"\"how many nodes\" questions instead of listing nodes and counting them.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ fleetStatsIn) (*sdk.CallToolResult, fleetStatsOut, error) {
		st, err := b.GetStats()
		if err != nil {
			return nil, fleetStatsOut{}, err
		}
		return nil, fleetStatsOut{
			TotalNodes:         st.TotalNodes,
			ActiveNodes:        st.ActiveNodes,
			InactiveNodes:      st.InactiveNodes,
			InactiveHours:      st.InactiveHours,
			TotalActiveQueries: st.TotalActiveQueries,
			TotalActiveCarves:  st.TotalActiveCarves,
			Environments:       envStats(st.Environments),
		}, nil
	})
}

func envStats(in []apiclient.EnvStats) []EnvironmentStats {
	out := make([]EnvironmentStats, 0, len(in))
	for _, e := range in {
		out = append(out, EnvironmentStats{
			InactiveHours: e.InactiveHours,
			Name:          e.Name,
			TotalNodes:    e.TotalNodes,
			ActiveNodes:   e.ActiveNodes,
			InactiveNodes: e.InactiveNodes,
			Linux:         e.PlatformCounts.Linux,
			Darwin:        e.PlatformCounts.Darwin,
			Windows:       e.PlatformCounts.Windows,
			Other:         e.PlatformCounts.Other,
		})
	}
	return out
}
