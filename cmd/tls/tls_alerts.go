package main

import (
	"context"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/vulns"
)

// tls_alerts.go — adapters wiring pkg/alerts to the osctrl-tls managers.

// tlsNodeSource adapts the nodes manager to the alert watcher's
// NodeSource. Inactive thresholds are resolved per environment from the
// settings manager, falling back to the global setting then the default.
type tlsNodeSource struct {
	nodes    *nodes.NodeManager
	settings *settings.Settings
	envs     *environments.EnvManager
}

// newTLSNodeSource builds the source over the package-level managers
// wired in the TLS service.
func newTLSNodeSource(nodesMgr *nodes.NodeManager, settingsMgr *settings.Settings, envsMgr *environments.EnvManager) *tlsNodeSource {
	return &tlsNodeSource{nodes: nodesMgr, settings: settingsMgr, envs: envsMgr}
}

// threshold resolves the inactive-hours setting for an environment.
func (s *tlsNodeSource) threshold(envID uint) int64 {
	if s.settings != nil {
		if h := s.settings.InactiveHours(envID); h > 0 {
			return h
		}
	}
	return settings.DefaultInactiveHours
}

// snapshotsByEnv runs the given target query per environment so the
// inactive threshold applies correctly — a single global query would use
// the wrong cutoff for environments with custom thresholds.
func (s *tlsNodeSource) snapshotsByEnv(ctx context.Context, target string) ([]alerts.NodeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	all, err := s.envs.All()
	if err != nil {
		return nil, err
	}
	var out []alerts.NodeSnapshot
	for _, env := range all {
		threshold := s.threshold(env.ID)
		nds, err := s.nodes.GetByEnv(env.Name, target, threshold)
		if err != nil {
			continue // one env failing must not drop the others
		}
		active := target == nodes.ActiveNodes
		for _, n := range nds {
			out = append(out, alerts.NodeSnapshot{
				UUID:          n.UUID,
				EnvironmentID: env.ID,
				Environment:   env.Name,
				Hostname:      n.Hostname,
				Active:        active,
				LastSeen:      n.LastSeen,
			})
		}
	}
	return out, nil
}

// InactiveNodes implements alerts.NodeSource.
func (s *tlsNodeSource) InactiveNodes(ctx context.Context) ([]alerts.NodeSnapshot, error) {
	return s.snapshotsByEnv(ctx, nodes.InactiveNodes)
}

// ActiveNodes implements alerts.NodeSource.
func (s *tlsNodeSource) ActiveNodes(ctx context.Context) ([]alerts.NodeSnapshot, error) {
	return s.snapshotsByEnv(ctx, nodes.ActiveNodes)
}

// tlsFindingSource adapts the vulnerability inventory to the alert
// watcher's FindingSource, adding environment names.
type tlsFindingSource struct {
	inv  *vulns.Inventory
	envs *environments.EnvManager
}

func newTLSFindingSource(inv *vulns.Inventory, envsMgr *environments.EnvManager) *tlsFindingSource {
	return &tlsFindingSource{inv: inv, envs: envsMgr}
}

// FindingsAfter implements alerts.FindingSource.
func (s *tlsFindingSource) FindingsAfter(ctx context.Context, afterID uint, limit int) ([]alerts.FindingSnapshot, error) {
	rows, err := s.inv.FindingsAfter(ctx, afterID, limit)
	if err != nil {
		return nil, err
	}
	return s.snapshots(rows), nil
}

// EscalationsAfter implements alerts.FindingSource.
func (s *tlsFindingSource) EscalationsAfter(ctx context.Context, afterID uint, limit int) ([]alerts.FindingSnapshot, error) {
	rows, err := s.inv.EscalationsAfter(ctx, afterID, limit)
	if err != nil {
		return nil, err
	}
	return s.snapshots(rows), nil
}

// snapshots converts feed rows, adding environment names.
func (s *tlsFindingSource) snapshots(rows []vulns.NewFinding) []alerts.FindingSnapshot {
	names := map[uint]string{}
	out := make([]alerts.FindingSnapshot, 0, len(rows))
	for _, r := range rows {
		name, ok := names[r.EnvironmentID]
		if !ok {
			if env, err := s.envs.GetByID(r.EnvironmentID); err == nil {
				name = env.Name
			}
			names[r.EnvironmentID] = name
		}
		out = append(out, alerts.FindingSnapshot{
			ID: r.ID, NodeUUID: r.NodeUUID, Hostname: r.Hostname,
			EnvironmentID: r.EnvironmentID, Environment: name,
			AdvisoryID: r.AdvisoryID, Package: r.Package,
			InstalledVersion: r.InstalledVersion, FixedVersion: r.FixedVersion,
			Severity: r.Severity, KEV: r.KEV,
			Escalated: r.Escalated, PrevSeverity: r.PrevSeverity, PrevKEV: r.PrevKEV,
		})
	}
	return out
}

// LatestFindingID implements alerts.FindingSource.
func (s *tlsFindingSource) LatestFindingID(ctx context.Context) (uint, error) {
	return s.inv.LatestFindingID(ctx)
}

// LatestEscalationID implements alerts.FindingSource.
func (s *tlsFindingSource) LatestEscalationID(ctx context.Context) (uint, error) {
	return s.inv.LatestEscalationID(ctx)
}
