package vulns

import (
	"context"
)

// alerting.go — the feed osctrl-tls's vulnerability alert watcher reads.

// NewFinding is one open confirmed finding for the alert watcher.
type NewFinding struct {
	ID               uint
	NodeUUID         string
	Hostname         string
	EnvironmentID    uint
	AdvisoryID       string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	KEV              bool
}

// FindingsAfter lists open confirmed findings with id > afterID, lowest id
// first, at most limit, with the node's hostname (empty when the node was
// deleted). "Possible" findings never alert, and a finding resolved before
// the watcher saw it is no longer news.
func (inv *Inventory) FindingsAfter(ctx context.Context, afterID uint, limit int) ([]NewFinding, error) {
	out := []NewFinding{}
	err := inv.DB.WithContext(ctx).Table("vuln_findings AS f").
		Select("f.id, f.node_uuid, f.environment_id, f.advisory_id, f.package, f.installed_version, "+
			"f.fixed_version, f.severity, f.kev, COALESCE(n.hostname, '') AS hostname").
		Joins("LEFT JOIN osquery_nodes AS n ON n.uuid = f.node_uuid AND n.deleted_at IS NULL").
		Where("f.id > ? AND f.confidence = ? AND f.resolved_at IS NULL", afterID, ConfidenceConfirmed).
		Order("f.id").Limit(limit).
		Scan(&out).Error
	return out, err
}

// LatestFindingID returns the highest finding id, 0 when there is none.
func (inv *Inventory) LatestFindingID(ctx context.Context) (uint, error) {
	var id uint
	err := inv.DB.WithContext(ctx).Model(&Finding{}).Select("COALESCE(MAX(id), 0)").Scan(&id).Error
	return id, err
}
