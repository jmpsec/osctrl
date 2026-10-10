package vulns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MaxRowsPerCategory bounds one snapshot. A bigger result is rejected rather
// than truncated: a truncated inventory reads as "not vulnerable".
const MaxRowsPerCategory = 50000

const maxFieldLen = 255

// packageCategories are the inventory categories that hold packages.
var packageCategories = map[string]bool{
	CategoryDeb: true, CategoryRPM: true, CategoryPython: true, CategoryNPM: true,
}

// Inventory stores the software nodes report through the osctrl:vuln:
// scheduled queries. It is the only part of this feature osctrl-tls runs.
type Inventory struct {
	DB  *gorm.DB
	now func() time.Time
}

// NewInventory migrates the vulnerability tables and returns the store.
func NewInventory(db *gorm.DB) (*Inventory, error) {
	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("migrate vulnerability tables: %w", err)
	}
	return &Inventory{DB: db, now: time.Now}, nil
}

// IsVulnQuery reports whether a scheduled query's results are inventory.
func IsVulnQuery(name string) bool { return strings.HasPrefix(name, QueryPrefix) }

// Ingest stores every osctrl:vuln: snapshot in results. Differential results
// are ignored: the profile schedules snapshots, and an added/removed row is
// not a whole inventory to replace the stored one with.
func (inv *Inventory) Ingest(nodeUUID string, envID uint, results []types.LogResultData) {
	for _, r := range results {
		if !IsVulnQuery(r.Name) || r.Action != "snapshot" {
			continue
		}
		category := strings.TrimPrefix(r.Name, QueryPrefix)
		if err := inv.ingestSnapshot(nodeUUID, envID, category, r.Columns); err != nil {
			log.Warn().Err(err).Str("node", nodeUUID).Str("query", r.Name).Msg("vulns: inventory not stored")
		}
	}
}

// row is one osquery result row. Values are kept raw because osquery logs
// numbers as numbers when --log_numerics_as_numbers is set.
type row map[string]json.RawMessage

func (r row) get(key string) string {
	raw, ok := r[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(raw))
}

func (inv *Inventory) ingestSnapshot(nodeUUID string, envID uint, category string, columns json.RawMessage) error {
	var rows []row
	if trimmed := bytes.TrimSpace(columns); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return fmt.Errorf("parse rows: %w", err)
		}
	}
	if len(rows) > MaxRowsPerCategory {
		return fmt.Errorf("%d rows exceeds the %d row limit", len(rows), MaxRowsPerCategory)
	}
	now := inv.now()
	if category == CategoryOS {
		if len(rows) == 0 {
			return nil
		}
		return inv.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node_uuid"}},
			DoUpdates: clause.AssignmentColumns([]string{"environment_id", "os_platform", "os_version", "os_major", "inventory_at"}),
		}).Create(&NodeState{
			NodeUUID:      nodeUUID,
			EnvironmentID: envID,
			OSPlatform:    clipTo(rows[0].get("platform"), 64),
			OSVersion:     clipTo(rows[0].get("version"), 128),
			OSMajor:       clipTo(rows[0].get("major"), 16),
			InventoryAt:   now,
		}).Error
	}
	if !packageCategories[category] {
		return fmt.Errorf("unknown inventory category %q", category)
	}
	software := normalizeRows(category, rows)
	return inv.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("node_uuid = ? AND category = ?", nodeUUID, category).Delete(&NodeSoftware{}).Error; err != nil {
			return err
		}
		for i := range software {
			software[i].NodeUUID = nodeUUID
			software[i].EnvironmentID = envID
			software[i].Category = category
			software[i].LastSeen = now
		}
		if len(software) > 0 {
			if err := tx.CreateInBatches(software, 500).Error; err != nil {
				return err
			}
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node_uuid"}},
			DoUpdates: clause.AssignmentColumns([]string{"environment_id", "inventory_at"}),
		}).Create(&NodeState{NodeUUID: nodeUUID, EnvironmentID: envID, InventoryAt: now}).Error
	})
}

// normalizeRows turns osquery rows into packages. Rows without a name are
// dropped; they cannot be matched against anything.
func normalizeRows(category string, rows []row) []NodeSoftware {
	out := make([]NodeSoftware, 0, len(rows))
	for _, r := range rows {
		sw := NodeSoftware{Name: r.get("name"), Version: r.get("version"), Arch: r.get("arch")}
		switch category {
		case CategoryDeb:
			// dpkg writes "src (version)" when the source version differs.
			if f := strings.Fields(r.get("source")); len(f) > 0 {
				sw.SourceName = f[0]
			}
		case CategoryRPM:
			if rel := r.get("release"); rel != "" {
				sw.Version += "-" + rel
			}
			if epoch := r.get("epoch"); epoch != "" && epoch != "0" {
				sw.Version = epoch + ":" + sw.Version
			}
			sw.SourceName = rpmSourceName(r.get("source"))
			sw.Vendor = r.get("vendor")
		}
		if sw.Name == "" {
			continue
		}
		sw.Name, sw.SourceName, sw.Version = clip(sw.Name), clip(sw.SourceName), clip(sw.Version)
		sw.Arch, sw.Vendor = clipTo(sw.Arch, 32), clip(sw.Vendor)
		out = append(out, sw)
	}
	return out
}

// rpmSourceName turns "openssl-3.0.7-27.el9.src.rpm" into "openssl".
func rpmSourceName(src string) string {
	s, ok := strings.CutSuffix(src, ".src.rpm")
	if !ok {
		return ""
	}
	for range 2 {
		i := strings.LastIndex(s, "-")
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}

func clip(s string) string { return clipTo(s, maxFieldLen) }

// clipTo cuts s to at most n bytes without splitting a UTF-8 character,
// which Postgres would reject along with the whole snapshot.
func clipTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
