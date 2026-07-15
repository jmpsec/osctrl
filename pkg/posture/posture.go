package posture

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// QueryPrefix is the prefix that identifies scheduled queries whose result
// logs should be ingested as posture data. Configurable via the
// --posture-query-prefix flag. Default: "osctrl:posture:".
//
// Recommended practice: set the osquery schedule interval for posture
// queries to once per day (86400 seconds). Posture data — installed
// packages, users, disk encryption state — changes infrequently, and
// daily collection is sufficient for compliance audits without
// overloading agents or the logging pipeline.
var QueryPrefix = "osctrl:posture:"

// SetPrefix sets the global query prefix. Called once at startup from
// the flag value. Empty string disables posture ingestion entirely.
func SetPrefix(prefix string) {
	QueryPrefix = prefix
}

// IsPostureQuery returns true if the query name starts with the posture
// prefix. When the prefix is empty, all queries are treated as non-posture.
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
	NodeUUID    string    `gorm:"index:idx_posture_node,composite" json:"node_uuid"`
	Environment string    `gorm:"index:idx_posture_env" json:"environment"`
	Category    string    `gorm:"index:idx_posture_node,composite;type:varchar(64)" json:"category"`
	// QueryName is the full osquery scheduled-query name including prefix.
	QueryName string `gorm:"type:varchar(255)" json:"query_name"`
	// RowCount is the number of rows in the result (e.g. 3 packages, 5 users).
	RowCount int `json:"row_count"`
	// Summary is a compact JSON snapshot of the result data. For small
	// results this is the full columns array; for large results it's
	// truncated to the first 100 rows to keep the record manageable.
	Summary string `gorm:"type:text" json:"summary"`
	// Snapshot is the raw columns JSON from the latest result, capped at
	// 256KB. Used for the detail view.
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
	if err := db.AutoMigrate(&NodePosture{}); err != nil {
		log.Fatal().Err(err).Msg("Failed to AutoMigrate table (node_posture)")
	}
	return pm
}

// IngestResult processes a single result log entry and upserts the
// posture record if the query name matches the posture prefix.
// Returns true if the entry was ingested as posture data.
func (pm *PostureManager) IngestResult(nodeUUID, environment, queryName string, columns json.RawMessage) bool {
	if pm == nil || !IsPostureQuery(queryName) {
		return false
	}
	category := PostureCategory(queryName)

	// Parse columns to count rows and build a summary.
	var rows []map[string]interface{}
	if err := json.Unmarshal(columns, &rows); err != nil {
		log.Warn().Err(err).Str("query", queryName).Msg("posture: failed to parse columns")
		return false
	}
	rowCount := len(rows)

	// Build summary: for small results, use the full data; for large
	// results, truncate to 100 rows.
	var summaryRows []map[string]interface{}
	if rowCount > 100 {
		summaryRows = rows[:100]
	} else {
		summaryRows = rows
	}
	summaryJSON, err := json.Marshal(summaryRows)
	if err != nil {
		log.Warn().Err(err).Msg("posture: failed to marshal summary")
		return false
	}

	// Cap snapshot at 256KB.
	snapshot := string(columns)
	if len(snapshot) > 256*1024 {
		snapshot = snapshot[:256*1024]
	}

	uuid := strings.ToUpper(nodeUUID)
	now := time.Now()

	// Upsert: find existing record by (node_uuid, category), update or insert.
	var existing NodePosture
	result := pm.DB.Where("node_uuid = ? AND category = ?", uuid, category).First(&existing)
	if result.Error != nil {
		// New record
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
		if err := pm.DB.Create(&record).Error; err != nil {
			log.Warn().Err(err).Str("node", uuid).Str("category", category).Msg("posture: create failed")
		}
	} else {
		// Update existing
		updates := map[string]interface{}{
			"row_count":  rowCount,
			"summary":    string(summaryJSON),
			"snapshot":   snapshot,
			"last_seen":  now,
			"query_name": queryName,
		}
		if err := pm.DB.Model(&existing).Updates(updates).Error; err != nil {
			log.Warn().Err(err).Str("node", uuid).Str("category", category).Msg("posture: update failed")
		}
	}
	return true
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

// GetFleetSummary returns a per-category summary across all nodes in an env.
type FleetCategorySummary struct {
	Category  string `json:"category"`
	NodeCount int    `json:"node_count"`
	TotalRows int    `json:"total_rows"`
}

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
