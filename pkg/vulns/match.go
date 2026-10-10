package vulns

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const queryChunk = 500

// Matcher recomputes findings from stored inventory and advisories.
type Matcher struct {
	DB  *gorm.DB
	now func() time.Time
}

type findingKey struct{ advisory, ecosystem, pkg string }

// MatchNode recomputes one node's findings. Findings that no longer match are
// resolved, never deleted; ones that match again are reopened.
func (m *Matcher) MatchNode(nodeUUID string) error {
	start := m.now()
	var state NodeState
	if err := m.DB.Where("node_uuid = ?", nodeUUID).Limit(1).Find(&state).Error; err != nil {
		return err
	}
	var software []NodeSoftware
	if err := m.DB.Where("node_uuid = ?", nodeUUID).Find(&software).Error; err != nil {
		return err
	}
	synced, err := syncedDirs(m.DB)
	if err != nil {
		return err
	}
	envID := state.EnvironmentID
	if envID == 0 && len(software) > 0 {
		envID = software[0].EnvironmentID
	}
	osKey := OSKey(state.OSPlatform, state.OSVersion, state.OSMajor)

	unassessed := map[uint]bool{}
	byEco := map[string]map[string][]NodeSoftware{} // ecosystem → package key → installed
	for _, sw := range software {
		eco := ecosystemFor(sw.Category, osKey)
		dir, _, _ := strings.Cut(eco, ":")
		if eco == "" || !synced[dir] || !assessableVersion(sw.Version) {
			unassessed[sw.ID] = true
			continue
		}
		pkgs := byEco[eco]
		if pkgs == nil {
			pkgs = map[string][]NodeSoftware{}
			byEco[eco] = pkgs
		}
		names := []string{PackageKey(eco, sw.Name)}
		if sw.SourceName != "" && sw.SourceName != sw.Name {
			names = append(names, PackageKey(eco, sw.SourceName))
		}
		for _, n := range names {
			pkgs[n] = append(pkgs[n], sw)
		}
	}

	found := map[findingKey]Finding{}
	for eco, pkgs := range byEco {
		for chunk := range slices.Chunk(slices.Sorted(maps.Keys(pkgs)), queryChunk) {
			var affected []Affected
			if err := m.DB.Where("ecosystem = ? AND package IN ?", eco, chunk).Find(&affected).Error; err != nil {
				return err
			}
			for _, a := range affected {
				var ranges []Range
				var versions []string
				if json.Unmarshal([]byte(a.Ranges), &ranges) != nil || json.Unmarshal([]byte(a.Versions), &versions) != nil {
					log.Warn().Str("advisory", a.AdvisoryID).Msg("vulns: unreadable affected row")
					continue
				}
				for _, sw := range pkgs[a.Package] {
					hit, fixed, err := isAffected(eco, sw.Version, ranges, versions)
					if err != nil {
						unassessed[sw.ID] = true
						continue
					}
					key := findingKey{a.AdvisoryID, eco, a.Package}
					if _, dup := found[key]; !hit || dup {
						continue
					}
					found[key] = Finding{
						NodeUUID: nodeUUID, EnvironmentID: envID, AdvisoryID: a.AdvisoryID,
						Ecosystem: eco, Package: a.Package, InstalledVersion: sw.Version,
						FixedVersion: clip(fixed), Confidence: ConfidenceConfirmed, Severity: SeverityUnknown,
					}
				}
			}
		}
	}
	if err := m.copyAdvisoryFlags(found); err != nil {
		return err
	}
	return m.DB.Transaction(func(tx *gorm.DB) error {
		return persistFindings(tx, nodeUUID, envID, found, len(unassessed), start)
	})
}

// syncedDirs returns the OSV directories that have synced successfully. A
// package in any other ecosystem is not assessed: an empty advisory table is
// not a clean bill of health.
func syncedDirs(db *gorm.DB) (map[string]bool, error) {
	var sources []string
	if err := db.Model(&SyncState{}).Where("last_success IS NOT NULL").Pluck("source", &sources).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, s := range sources {
		if dir, ok := strings.CutPrefix(s, osvSourcePrefix); ok {
			out[dir] = true
		}
	}
	return out, nil
}

func (m *Matcher) copyAdvisoryFlags(found map[findingKey]Finding) error {
	ids := map[string]bool{}
	for k := range found {
		ids[k.advisory] = true
	}
	flags := map[string]Advisory{}
	for chunk := range slices.Chunk(slices.Sorted(maps.Keys(ids)), queryChunk) {
		var rows []Advisory
		if err := m.DB.Select("id", "severity", "kev").Where("id IN ?", chunk).Find(&rows).Error; err != nil {
			return err
		}
		for _, a := range rows {
			flags[a.ID] = a
		}
	}
	for k, f := range found {
		if a, ok := flags[k.advisory]; ok {
			f.Severity, f.KEV = a.Severity, a.KEV
			found[k] = f
		}
	}
	return nil
}

func persistFindings(tx *gorm.DB, nodeUUID string, envID uint, found map[findingKey]Finding, notAssessed int, now time.Time) error {
	var existing []Finding
	if err := tx.Where("node_uuid = ?", nodeUUID).Find(&existing).Error; err != nil {
		return err
	}
	for _, e := range existing {
		key := findingKey{e.AdvisoryID, e.Ecosystem, e.Package}
		f, ok := found[key]
		if !ok {
			if e.ResolvedAt == nil {
				if err := tx.Model(&Finding{}).Where("id = ?", e.ID).Update("resolved_at", now).Error; err != nil {
					return err
				}
			}
			continue
		}
		delete(found, key)
		if err := tx.Model(&Finding{}).Where("id = ?", e.ID).Updates(map[string]any{
			"environment_id":    envID,
			"installed_version": f.InstalledVersion,
			"fixed_version":     f.FixedVersion,
			"severity":          f.Severity,
			"kev":               f.KEV,
			"last_seen":         now,
			"resolved_at":       nil,
		}).Error; err != nil {
			return err
		}
	}
	created := make([]Finding, 0, len(found))
	for _, f := range found {
		f.FirstSeen, f.LastSeen = now, now
		created = append(created, f)
	}
	if len(created) > 0 {
		if err := tx.CreateInBatches(created, 500).Error; err != nil {
			return err
		}
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_uuid"}},
		DoUpdates: clause.AssignmentColumns([]string{"matched_at", "not_assessed"}),
	}).Create(&NodeState{NodeUUID: nodeUUID, EnvironmentID: envID, MatchedAt: &now, NotAssessed: notAssessed}).Error
}
