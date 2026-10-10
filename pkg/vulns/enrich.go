package vulns

import "gorm.io/gorm"

// enrichSeverity gives OSV advisories that carry no CVSS of their own the
// score of their highest-scored aliased NVD CVE: many Debian and Ubuntu
// records have none. CVSSFrom records the CVE, so a later run can update the
// score or, once the CVE is gone (NVD turned off), clear it again. Only rows
// whose value changes are written.
func enrichSeverity(db *gorm.DB) error {
	var candidates []struct {
		AdvisoryID string
		CVE        string
		CVSSVector string
		CVSSScore  float64
	}
	if err := db.Raw(`SELECT al.advisory_id, n.id AS cve, n.cvss_vector, n.cvss_score
		FROM vuln_aliases al
		JOIN vuln_advisories a ON a.id = al.advisory_id AND a.source = ? AND (a.cvss_vector = '' OR a.cvss_from <> '')
		JOIN vuln_advisories n ON n.id = al.alias AND n.source = ? AND n.cvss_vector <> ''`,
		AdvisorySourceOSV, AdvisorySourceNVD).Scan(&candidates).Error; err != nil {
		return err
	}
	type borrowed struct {
		cve, vector string
		score       float64
	}
	want := map[string]borrowed{}
	for _, c := range candidates {
		cur, ok := want[c.AdvisoryID]
		if !ok || c.CVSSScore > cur.score || (c.CVSSScore == cur.score && c.CVE < cur.cve) {
			want[c.AdvisoryID] = borrowed{c.CVE, c.CVSSVector, c.CVSSScore}
		}
	}
	var current []Advisory
	if err := db.Select("id", "cvss_vector", "cvss_score", "cvss_from").
		Where("source = ? AND cvss_from <> ''", AdvisorySourceOSV).Find(&current).Error; err != nil {
		return err
	}
	have := map[string]Advisory{}
	for _, a := range current {
		have[a.ID] = a
	}
	return db.Transaction(func(tx *gorm.DB) error {
		for _, a := range current {
			if _, ok := want[a.ID]; ok {
				continue
			}
			if err := tx.Model(&Advisory{}).Where("id = ?", a.ID).Updates(map[string]any{
				"cvss_vector": "", "cvss_score": 0, "severity": SeverityUnknown, "cvss_from": "",
			}).Error; err != nil {
				return err
			}
		}
		for id, b := range want {
			if h, ok := have[id]; ok && h.CVSSFrom == b.cve && h.CVSSVector == b.vector && h.CVSSScore == b.score {
				continue
			}
			if err := tx.Model(&Advisory{}).Where("id = ?", id).Updates(map[string]any{
				"cvss_vector": b.vector, "cvss_score": b.score, "severity": severityFromScore(b.score), "cvss_from": b.cve,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
