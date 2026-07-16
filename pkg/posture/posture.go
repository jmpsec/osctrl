package posture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DefaultQueryPrefix identifies scheduled queries whose result logs should be
// ingested as posture data by default.
//
// Recommended practice: set the osquery schedule interval for posture
// queries to once per day (86400 seconds). Posture data — installed
// packages, users, disk encryption state — changes infrequently, and
// daily collection is sufficient for compliance audits without
// overloading agents or the logging pipeline.
const DefaultQueryPrefix = "osctrl:posture:"

// QueryPrefix is the active posture query prefix. It is configured once at TLS
// startup. Empty disables posture ingestion.
var QueryPrefix = DefaultQueryPrefix

// SetPrefix sets the active posture query prefix.
func SetPrefix(prefix string) {
	QueryPrefix = prefix
}

// IsPostureQuery returns true if the query name starts with the posture
// prefix.
func IsPostureQuery(name string) bool {
	return QueryPrefix != "" && strings.HasPrefix(name, QueryPrefix)
}

// PostureCategory extracts the category name from a posture query name.
// e.g. "osctrl:posture:packages" → "packages"
func PostureCategory(name string) string {
	if !IsPostureQuery(name) {
		return ""
	}
	return strings.TrimPrefix(name, QueryPrefix)
}

// NodePosture stores the latest snapshot of a single posture category
// for one node. Updated (upserted) every time a matching result log arrives.
type NodePosture struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	NodeUUID    string    `gorm:"type:varchar(36);uniqueIndex:idx_posture_node_category" json:"node_uuid"`
	Environment string    `gorm:"index:idx_posture_env" json:"environment"`
	Category    string    `gorm:"uniqueIndex:idx_posture_node_category;type:varchar(64)" json:"category"`
	// QueryName is the full osquery scheduled-query name including prefix.
	QueryName string `gorm:"type:varchar(255)" json:"query_name"`
	// RowCount is the number of rows in the result (e.g. 3 packages, 5 users).
	RowCount int `json:"row_count"`
	// Summary is a compact JSON snapshot of the result data. For small
	// results this is the full columns array; for large results it's
	// truncated to the first 100 rows to keep the record manageable.
	Summary string `gorm:"type:text" json:"summary"`
	// Snapshot is the raw columns JSON from the latest result, capped at
	// 256KB. Used for detail views and compatibility with existing posture data.
	Snapshot string `gorm:"type:text" json:"-"`
	// FirstSeen is when this category was first observed for this node.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `gorm:"index" json:"last_seen"`
}

// TableName overrides the default table name.
func (NodePosture) TableName() string { return "node_posture" }

// PostureManager manages the node posture table.
type PostureManager struct {
	DB *gorm.DB
}

// NewPostureManager creates the manager and auto-migrates the table.
func NewPostureManager(db *gorm.DB) *PostureManager {
	pm := &PostureManager{DB: db}
	if err := migrateNodePosture(db); err != nil {
		log.Fatal().Err(err).Msg("Failed to AutoMigrate table (node_posture)")
	}
	return pm
}

const postureMigrationAttempts = 5

// migrateNodePosture removes duplicates allowed by the original schema before
// adding the unique node/category index. Retrying makes concurrent API/TLS
// startup idempotent if another instance changes the table between cleanup and
// index creation.
func migrateNodePosture(db *gorm.DB) error {
	var lastErr error
	for attempt := 0; attempt < postureMigrationAttempts; attempt++ {
		if db.Migrator().HasTable(&NodePosture{}) && !db.Migrator().HasIndex(&NodePosture{}, "idx_posture_node_category") {
			if err := deduplicateNodePosture(db); err != nil {
				lastErr = err
				continue
			}
		}
		if err := db.AutoMigrate(&NodePosture{}); err != nil {
			lastErr = fmt.Errorf("auto-migrate posture table: %w", err)
			continue
		}
		if db.Migrator().HasIndex(&NodePosture{}, "idx_posture_node") {
			if err := db.Migrator().DropIndex(&NodePosture{}, "idx_posture_node"); err != nil && db.Migrator().HasIndex(&NodePosture{}, "idx_posture_node") {
				lastErr = fmt.Errorf("drop legacy posture index: %w", err)
				continue
			}
		}
		return nil
	}
	return fmt.Errorf("migrate posture table after %d attempts: %w", postureMigrationAttempts, lastErr)
}

func deduplicateNodePosture(db *gorm.DB) error {
	type postureKey struct {
		NodeUUID string
		Category string
	}
	type postureKeeper struct {
		ID        uint
		UpdatedAt time.Time
	}

	for {
		var keys []postureKey
		if err := db.Model(&NodePosture{}).
			Select("node_uuid", "category").
			Group("node_uuid, category").
			Having("COUNT(*) > 1").
			Limit(100).
			Find(&keys).Error; err != nil {
			return fmt.Errorf("find duplicate posture groups: %w", err)
		}
		if len(keys) == 0 {
			return nil
		}

		for _, key := range keys {
			var keeper postureKeeper
			if err := db.Model(&NodePosture{}).
				Select("id", "updated_at").
				Where("node_uuid = ? AND category = ?", key.NodeUUID, key.Category).
				Order("updated_at DESC, id DESC").
				First(&keeper).Error; err != nil {
				return fmt.Errorf("select posture row to retain: %w", err)
			}
			if err := db.Unscoped().
				Where("node_uuid = ? AND category = ?", key.NodeUUID, key.Category).
				Where("updated_at < ? OR (updated_at = ? AND id < ?)", keeper.UpdatedAt, keeper.UpdatedAt, keeper.ID).
				Delete(&NodePosture{}).Error; err != nil {
				return fmt.Errorf("remove duplicate posture rows: %w", err)
			}
		}
	}
}

// IngestResult processes a single result log entry and upserts the
// posture record if the query name matches the posture prefix.
func (pm *PostureManager) IngestResult(nodeUUID, environment, queryName string, columns json.RawMessage) error {
	if pm == nil {
		return fmt.Errorf("posture manager is nil")
	}
	if !IsPostureQuery(queryName) {
		return fmt.Errorf("query %q is not a posture query", queryName)
	}
	category := PostureCategory(queryName)

	trimmed := bytes.TrimSpace(columns)
	rows := []json.RawMessage{}
	if len(trimmed) > 0 {
		switch trimmed[0] {
		case '[':
			if err := json.Unmarshal(trimmed, &rows); err != nil {
				return fmt.Errorf("parse posture rows: %w", err)
			}
			if rows == nil {
				rows = []json.RawMessage{}
			}
		case '{':
			if !json.Valid(trimmed) {
				return fmt.Errorf("parse posture row: invalid JSON")
			}
			rows = []json.RawMessage{json.RawMessage(trimmed)}
		default:
			return fmt.Errorf("posture columns must be a JSON object or array")
		}
	}
	for i, row := range rows {
		row = bytes.TrimSpace(row)
		if len(row) == 0 || row[0] != '{' || !json.Valid(row) {
			return fmt.Errorf("posture row %d must be a JSON object", i)
		}
		rows[i] = row
	}
	rowCount := len(rows)

	summaryRows := rows
	if len(summaryRows) > 100 {
		summaryRows = summaryRows[:100]
	}
	if summaryRows == nil {
		summaryRows = []json.RawMessage{}
	}
	summaryJSON, err := json.Marshal(summaryRows)
	if err != nil {
		return fmt.Errorf("marshal posture summary: %w", err)
	}
	snapshot := string(trimmed)
	if snapshot == "" {
		snapshot = "[]"
	}
	if len(snapshot) > 256*1024 {
		snapshot = snapshot[:256*1024]
	}

	uuid := strings.ToUpper(nodeUUID)
	now := time.Now()
	record := NodePosture{
		NodeUUID:    uuid,
		Environment: environment,
		Category:    category,
		QueryName:   queryName,
		RowCount:    rowCount,
		Summary:     string(summaryJSON),
		Snapshot:    snapshot,
		FirstSeen:   now,
		LastSeen:    now,
	}
	return pm.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "node_uuid"}, {Name: "category"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"environment": environment,
			"query_name":  queryName,
			"row_count":   rowCount,
			"summary":     string(summaryJSON),
			"snapshot":    snapshot,
			"last_seen":   now,
			"updated_at":  now,
		}),
	}).Create(&record).Error
}

// GetByNode returns all posture categories for a node, ordered by category.
func (pm *PostureManager) GetByNode(nodeUUID string) ([]NodePosture, error) {
	var records []NodePosture
	err := pm.DB.Where("node_uuid = ?", strings.ToUpper(nodeUUID)).
		Order("category ASC").Find(&records).Error
	return records, err
}

// GetByNodeCategory returns a single posture category for a node.
func (pm *PostureManager) GetByNodeCategory(nodeUUID, category string) (*NodePosture, error) {
	var record NodePosture
	err := pm.DB.Where("node_uuid = ? AND category = ?", strings.ToUpper(nodeUUID), category).
		First(&record).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// FleetCategorySummary is a per-category summary across all nodes in an environment.
type FleetCategorySummary struct {
	Category  string `json:"category"`
	NodeCount int    `json:"node_count"`
	TotalRows int    `json:"total_rows"`
}

// GetFleetSummary returns per-category posture counts across all nodes in an environment.
func (pm *PostureManager) GetFleetSummary(environment string) ([]FleetCategorySummary, error) {
	var results []FleetCategorySummary
	err := pm.DB.Model(&NodePosture{}).
		Select("category, COUNT(*) as node_count, SUM(row_count) as total_rows").
		Where("environment = ?", environment).
		Group("category").
		Order("category ASC").
		Scan(&results).Error
	return results, err
}
