package vulns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type kevFeed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// syncKEV replaces the KEV catalog and refreshes the flags derived from it.
func syncKEV(ctx context.Context, db *gorm.DB, f fetcher, url string, now time.Time) error {
	err := func() error {
		raw, err := f.readAll(ctx, url)
		if err != nil {
			return err
		}
		var feed kevFeed
		if err := json.Unmarshal(raw, &feed); err != nil {
			return err
		}
		seen := map[string]bool{}
		var rows []KEV
		for _, v := range feed.Vulnerabilities {
			id := strings.TrimSpace(v.CVEID)
			if strings.HasPrefix(id, "CVE-") && len(id) <= 32 && !seen[id] {
				seen[id] = true
				rows = append(rows, KEV{CVEID: id})
			}
		}
		if len(rows) == 0 {
			// A truncated or wrong file must not clear every KEV flag.
			return errors.New("KEV feed lists no vulnerabilities")
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("1 = 1").Delete(&KEV{}).Error; err != nil {
				return err
			}
			return tx.CreateInBatches(rows, 500).Error
		}); err != nil {
			return err
		}
		if err := refreshFlags(db); err != nil {
			return err
		}
		return recordSuccess(db, sourceKEV, now, SyncResult{Written: len(rows)}, now)
	}()
	if err != nil {
		recordFailure(db, sourceKEV, err, now)
	}
	return err
}

// refreshFlags recomputes KEV on advisories and copies severity and KEV onto
// findings, so a feed update shows without re-matching every node.
func refreshFlags(db *gorm.DB) error {
	if err := db.Exec(`UPDATE vuln_advisories SET kev = EXISTS (
		SELECT 1 FROM vuln_aliases a JOIN vuln_kev k ON k.cve_id = a.alias
		WHERE a.advisory_id = vuln_advisories.id)`).Error; err != nil {
		return err
	}
	return db.Exec(`UPDATE vuln_findings SET
		kev = (SELECT a.kev FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id),
		severity = (SELECT a.severity FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id)
		WHERE EXISTS (SELECT 1 FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id)`).Error
}
