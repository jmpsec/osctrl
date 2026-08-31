package main

import (
	"context"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
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
