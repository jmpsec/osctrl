package osqueryversions

import "time"

// CountBehind returns, per environment id, the nodes with an osctrld report
// newer than fresh whose stored osquery version is lower than their effective
// target: an unexpired pin of the same environment, else the environment's
// target. Nodes without a target, with an unparseable version or on an
// unsupported platform (see NodePlatformSupported) are not counted.
// The table names are those of the nodes and osctrld status models, which this
// package must not import.
func (m *Manager) CountBehind(now time.Time, fresh time.Duration) (map[uint]int, error) {
	var nodes []struct {
		UUID           string
		EnvironmentID  uint
		OsqueryVersion string
	}
	err := m.db.Table("node_osctrld_status AS s").
		Select("n.uuid AS uuid, n.environment_id AS environment_id, n.osquery_version AS osquery_version").
		// The environment is part of the join: re-enrolling into another
		// environment leaves the old node row with the same UUID behind.
		Joins("JOIN osquery_nodes AS n ON n.uuid = s.node_uuid AND n.environment_id = s.environment_id").
		Where("s.reported_at >= ? AND n.deleted_at IS NULL AND n.osquery_version <> '' AND "+SupportedNodePlatformSQL("n.platform"), now.Add(-fresh)).
		Scan(&nodes).Error
	if err != nil {
		return nil, err
	}
	var targets []EnvTarget
	if err := m.db.Find(&targets).Error; err != nil {
		return nil, err
	}
	envTarget := make(map[uint]string, len(targets))
	for _, t := range targets {
		envTarget[t.EnvironmentID] = t.Version
	}
	var pins []NodePin
	if err := m.db.Find(&pins).Error; err != nil {
		return nil, err
	}
	pinned := make(map[string]NodePin, len(pins))
	for _, p := range pins {
		if !p.Expired(now) {
			pinned[p.NodeUUID] = p
		}
	}
	out := map[uint]int{}
	for _, n := range nodes {
		target := envTarget[n.EnvironmentID]
		if p, ok := pinned[n.UUID]; ok && p.EnvironmentID == n.EnvironmentID {
			target = p.Version
		}
		if target == "" {
			continue
		}
		if c, err := Compare(n.OsqueryVersion, target); err == nil && c < 0 {
			out[n.EnvironmentID]++
		}
	}
	return out, nil
}
