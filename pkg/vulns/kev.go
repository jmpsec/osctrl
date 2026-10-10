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
		if err := refreshFlags(db, now); err != nil {
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
// findings, so a feed update shows without re-matching every node. Borrowed
// NVD severities are applied first (enrich.go), and open confirmed findings
// that become known-exploited or more severe are recorded as escalations in
// the same transaction as the copy, so each is recorded once.
func refreshFlags(db *gorm.DB, now time.Time) error {
	if err := enrichSeverity(db); err != nil {
		return err
	}
	if err := db.Exec(`UPDATE vuln_advisories SET kev = EXISTS (
		SELECT 1 FROM vuln_aliases a JOIN vuln_kev k ON k.cve_id = a.alias
		WHERE a.advisory_id = vuln_advisories.id)`).Error; err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := recordEscalations(tx, now); err != nil {
			return err
		}
		return tx.Exec(`UPDATE vuln_findings SET
		kev = (SELECT a.kev FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id),
		severity = (SELECT a.severity FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id)
		WHERE EXISTS (SELECT 1 FROM vuln_advisories a WHERE a.id = vuln_findings.advisory_id)`).Error
	})
}

// recordEscalations notes open confirmed findings whose advisory became
// known-exploited or more severe than the finding says.
func recordEscalations(tx *gorm.DB, now time.Time) error {
	var rows []struct {
		ID          uint
		Severity    string
		KEV         bool
		NewSeverity string
		NewKEV      bool
	}
	if err := tx.Raw(`SELECT f.id, f.severity, f.kev, a.severity AS new_severity, a.kev AS new_kev
		FROM vuln_findings f JOIN vuln_advisories a ON a.id = f.advisory_id
		WHERE f.resolved_at IS NULL AND f.confidence = ? AND (f.severity <> a.severity OR f.kev <> a.kev)`,
		ConfidenceConfirmed).Scan(&rows).Error; err != nil {
		return err
	}
	var events []Escalation
	for _, r := range rows {
		if escalated(r.Severity, r.KEV, r.NewSeverity, r.NewKEV) {
			events = append(events, Escalation{FindingID: r.ID, PrevSeverity: r.Severity, PrevKEV: r.KEV, CreatedAt: now})
		}
	}
	if len(events) == 0 {
		return nil
	}
	return tx.CreateInBatches(events, 500).Error
}

// severityRank orders severities; unknown ranks below low.
var severityRank = map[string]int{SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4}

// escalated reports whether a finding became known-exploited or rose in
// severity.
func escalated(prevSeverity string, prevKEV bool, severity string, kev bool) bool {
	return (kev && !prevKEV) || severityRank[severity] > severityRank[prevSeverity]
}
