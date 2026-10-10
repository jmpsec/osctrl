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
	// CPE turns on name matching against NVD data (--vuln-nvd-enabled).
	CPE bool
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
	assessed := map[uint]bool{} // checked against an OSV feed
	var cpePackages []NodeSoftware
	byEco := map[string]map[string][]NodeSoftware{} // ecosystem → package key → installed
	for _, sw := range software {
		if cpeCategories[sw.Category] {
			// Matched by name against NVD, only while NVD is on and synced.
			if !m.CPE || !synced[cpeEcosystem] || !assessableVersion(sw.Version) {
				unassessed[sw.ID] = true
				continue
			}
			cpePackages = append(cpePackages, sw)
			continue
		}
		eco := ecosystemFor(sw.Category, osKey)
		dir, _, _ := strings.Cut(eco, ":")
		if eco == "" || !synced[dir] || !assessableVersion(sw.Version) {
			unassessed[sw.ID] = true
			continue
		}
		assessed[sw.ID] = true
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
	if err := m.matchCPE(nodeUUID, envID, cpePackages, found, unassessed); err != nil {
		return err
	}
	confirmed := 0
	for id := range assessed {
		if !unassessed[id] {
			confirmed++
		}
	}
	if err := m.copyAdvisoryFlags(found); err != nil {
		return err
	}
	return m.DB.Transaction(func(tx *gorm.DB) error {
		return persistFindings(tx, nodeUUID, envID, found, len(unassessed), confirmed, start)
	})
}

// matchCPE adds possible findings for packages matched by name against NVD
// CPE data. A version that cannot be compared is not assessed.
func (m *Matcher) matchCPE(nodeUUID string, envID uint, pkgs []NodeSoftware, found map[findingKey]Finding, unassessed map[uint]bool) error {
	if len(pkgs) == 0 {
		return nil
	}
	type candidates struct{ vendors, products []string }
	cands := make([]candidates, len(pkgs))
	wanted, vendorNames := map[string]bool{}, map[string]bool{}
	for i, sw := range pkgs {
		v, p := cpeCandidates(sw)
		cands[i] = candidates{v, p}
		for _, name := range p {
			wanted[name] = true
		}
		for _, name := range v {
			vendorNames[name] = true
		}
	}
	known := map[string]bool{} // candidate vendors that are CPE vendors
	for chunk := range slices.Chunk(slices.Sorted(maps.Keys(vendorNames)), queryChunk) {
		var listed []string
		if err := m.DB.Model(&CPEProduct{}).Distinct("vendor").Where("vendor IN ?", chunk).Pluck("vendor", &listed).Error; err != nil {
			return err
		}
		for _, v := range listed {
			known[v] = true
		}
	}
	byProduct := map[string][]string{}
	for chunk := range slices.Chunk(slices.Sorted(maps.Keys(wanted)), queryChunk) {
		var rows []CPEProduct
		if err := m.DB.Where("product IN ?", chunk).Find(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			byProduct[r.Product] = append(byProduct[r.Product], r.Vendor)
		}
	}
	byKey := map[string][]NodeSoftware{} // vendor:product → installed
	for i, sw := range pkgs {
		for _, key := range resolveCPE(cands[i].vendors, cands[i].products, byProduct, known) {
			byKey[key] = append(byKey[key], sw)
		}
	}
	for chunk := range slices.Chunk(slices.Sorted(maps.Keys(byKey)), queryChunk) {
		var affected []Affected
		if err := m.DB.Where("ecosystem = ? AND package IN ?", cpeEcosystem, chunk).Find(&affected).Error; err != nil {
			return err
		}
		for _, a := range affected {
			var ranges []cpeRange
			var versions []string
			if json.Unmarshal([]byte(a.Ranges), &ranges) != nil || json.Unmarshal([]byte(a.Versions), &versions) != nil {
				log.Warn().Str("advisory", a.AdvisoryID).Msg("vulns: unreadable CPE row")
				continue
			}
			for _, sw := range byKey[a.Package] {
				hit, fixed, err := cpeAffected(sw.Version, ranges, versions)
				if err != nil {
					unassessed[sw.ID] = true
					continue
				}
				key := findingKey{a.AdvisoryID, cpeEcosystem, a.Package}
				if _, dup := found[key]; !hit || dup {
					continue
				}
				found[key] = Finding{
					NodeUUID: nodeUUID, EnvironmentID: envID, AdvisoryID: a.AdvisoryID,
					Ecosystem: cpeEcosystem, Package: a.Package, InstalledVersion: sw.Version,
					FixedVersion: clip(fixed), Confidence: ConfidencePossible, Severity: SeverityUnknown,
				}
			}
		}
	}
	return nil
}

// syncedDirs returns the OSV directories that have synced successfully, and
// "cpe" once NVD has. A package in any other ecosystem is not assessed: an
// empty advisory table is not a clean bill of health.
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
		if s == sourceNVD {
			out[cpeEcosystem] = true
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

func persistFindings(tx *gorm.DB, nodeUUID string, envID uint, found map[findingKey]Finding, notAssessed, assessed int, now time.Time) error {
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
		DoUpdates: clause.AssignmentColumns([]string{"matched_at", "not_assessed", "assessed"}),
	}).Create(&NodeState{NodeUUID: nodeUUID, EnvironmentID: envID, MatchedAt: &now, NotAssessed: notAssessed, Assessed: assessed}).Error
}
