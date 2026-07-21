package queries

import (
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// QueryListPage is the canonical paginated-list result for queries.
type QueryListPage struct {
	Items      []DistributedQuery
	TotalItems int64
}

// QuerySortableColumns is the closed set of columns external callers may sort by.
// Enforced in GetByEnvTargetPaged. Mirrors the SortableColumns convention from pkg/nodes.
var QuerySortableColumns = map[string]string{
	"name":       "name",
	"creator":    "creator",
	"created":    "created_at",
	"type":       "type",
	"expected":   "expected",
	"executions": "executions",
	"errors":     "errors",
}

const (
	// QueryTargetPlatform defines platform as target
	QueryTargetPlatform string = "platform"
	// QueryTargetLocalname defines localname as target
	QueryTargetLocalname string = "localname"
	// QueryTargetEnvironment defines environment as target
	QueryTargetEnvironment string = "environment"
	// QueryTargetUUID defines uuid as target
	QueryTargetUUID string = "uuid"
	// StandardQueryType defines a regular query
	StandardQueryType string = "query"
	// CarveQueryType defines a regular query
	CarveQueryType string = "carve"
	// MetadataQueryType defines a regular query
	MetadataQueryType string = "metadata"
	// ConsoleQueryType defines a hidden accelerated query used by node consoles
	ConsoleQueryType string = "console"
)

const (
	// StatusActive defines active status constant
	StatusActive string = "ACTIVE"
	// StatusComplete defines complete status constant
	StatusComplete string = "COMPLETE"
	// StatusExpired defines expired status constant
	StatusExpired string = "EXPIRED"
)

const (
	// TargetAll for all queries but hidden
	TargetAll string = "all"
	// TargetAllFull for all queries including hidden ones
	TargetAllFull string = "all-full"
	// TargetActive for active queries
	TargetActive string = "active"
	// TargetHiddenActive for hidden active queries
	TargetHiddenActive string = "hidden-active"
	// TargetCompleted for completed queries
	TargetCompleted string = "completed"
	// TargetExpired for expired queries
	TargetExpired string = "expired"
	// TargetSaved for saved queries
	TargetSaved string = "saved"
	// TargetHiddenCompleted for hidden completed queries
	TargetHiddenCompleted string = "hidden-completed"
	// TargetDeleted for deleted queries
	TargetDeleted string = "deleted"
	// TargetHidden for hidden queries
	TargetHidden string = "hidden"
)

const (
	DistributedQueryStatusPending   string = "pending"
	DistributedQueryStatusCompleted string = "completed"
	DistributedQueryStatusError     string = "error"
	DistributedQueryStatusExpired   string = "expired"
)

// DistributedQuery as abstraction of a distributed query.
//
// Explicit JSON tags (rather than relying on Go's default-PascalCase
// behavior or an external view projection) so /api/v1/queries and
// /api/v1/carves responses match the SPA's snake_case contract directly.
// Fields here are equivalent to embedding gorm.Model — same schema and
// soft-delete semantics — just with field-level json tags.
type DistributedQuery struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	Name          string         `gorm:"not null;unique;index" json:"name"`
	Creator       string         `json:"creator"`
	Query         string         `json:"query"`
	Expected      int            `json:"expected"`
	Executions    int            `json:"executions"`
	Errors        int            `json:"errors"`
	Active        bool           `json:"active"`
	Hidden        bool           `json:"hidden"`
	Protected     bool           `json:"protected"`
	Completed     bool           `json:"completed"`
	Deleted       bool           `json:"deleted"`
	Expired       bool           `json:"expired"`
	Type          string         `json:"type"`
	Path          string         `json:"path"`
	EnvironmentID uint           `json:"environment_id"`
	ExtraData     string         `json:"extra_data"`
	Expiration    time.Time      `json:"expiration"`
	Target        string         `json:"target"`
	CarveStatus   string         `gorm:"-" json:"carve_status,omitempty"`
}

// NodeQuery links a node to a query
type NodeQuery struct {
	gorm.Model
	NodeID  uint   `gorm:"not null;index"`
	QueryID uint   `gorm:"not null;index"`
	Status  string `gorm:"type:varchar(10);default:'pending'"`
}

// DistributedQueryTarget to keep target logic for queries
type DistributedQueryTarget struct {
	gorm.Model
	Name  string `gorm:"index"`
	Type  string
	Value string
}

// QueryReadQueries to hold all the on-demand queries
type QueryReadQueries map[string]string

// Queries to handle on-demand queries
type Queries struct {
	DB *gorm.DB
}

// CreateQueries to initialize the queries struct
func CreateQueries(backend *gorm.DB) *Queries {
	// var q *Queries
	q := &Queries{DB: backend}

	// table node_queries
	if err := backend.AutoMigrate(&NodeQuery{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (node_queries): %v", err)
	}
	// table distributed_queries
	if err := backend.AutoMigrate(&DistributedQuery{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (distributed_queries): %v", err)
	}
	// table distributed_query_targets
	if err := backend.AutoMigrate(&DistributedQueryTarget{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (distributed_query_targets): %v", err)
	}
	// table saved_queries
	if err := backend.AutoMigrate(&SavedQuery{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (saved_queries): %v", err)
	}
	return q
}

func (q *Queries) NodeQueries(node nodes.OsqueryNode) (QueryReadQueries, bool, error) {

	var results []struct {
		Name  string
		Query string
		Type  string
	}

	q.DB.Table("distributed_queries dq").
		Select("dq.name, dq.query, dq.type").
		Joins("JOIN node_queries nq ON dq.id = nq.query_id").
		Where("nq.node_id = ? AND nq.status = ?", node.ID, DistributedQueryStatusPending).
		Scan(&results)

	if len(results) == 0 {
		return QueryReadQueries{}, false, nil
	}

	qs := make(QueryReadQueries)
	accelerate := false
	for _, _q := range results {
		qs[_q.Name] = _q.Query
		if _q.Type == ConsoleQueryType {
			accelerate = true
		}
	}

	return qs, accelerate, nil
}

// Gets all queries by target (active/completed/all/all-full/deleted/hidden/expired)
func (q *Queries) Gets(target, qtype string, envid uint) ([]DistributedQuery, error) {
	var queries []DistributedQuery
	if qtype == ConsoleQueryType {
		return queries, nil
	}
	switch target {
	case TargetActive:
		if err := q.DB.Where(
			"active = ? AND completed = ? AND deleted = ? AND expired = ? AND type = ? AND environment_id = ?",
			true,
			false,
			false,
			false,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetCompleted:
		if err := q.DB.Where(
			"active = ? AND completed = ? AND deleted = ? AND expired = ? AND type = ? AND environment_id = ?",
			false,
			true,
			false,
			false,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetHiddenCompleted:
		if err := q.DB.Where(
			"active = ? AND completed = ? AND deleted = ? AND hidden = ? AND type = ? AND environment_id = ?",
			false,
			true,
			false,
			true,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetAllFull:
		if err := q.DB.Where(
			"deleted = ? AND type = ? AND environment_id = ?",
			false,
			qtype, envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetAll:
		if err := q.DB.Where(
			"deleted = ? AND hidden = ? AND type = ? AND environment_id = ?",
			false,
			false,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetDeleted:
		if err := q.DB.Where("deleted = ? AND type = ? AND environment_id = ?",
			true,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetHidden:
		if err := q.DB.Where(
			"deleted = ? AND hidden = ? AND type = ? AND environment_id = ?",
			false,
			true,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetExpired:
		if err := q.DB.Where(
			"active = ? AND expired = ? AND deleted = ? AND type = ? AND environment_id = ?",
			false,
			true,
			false,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	}
	return queries, nil
}

// Checks if a query exists in an environment, regardless of the status
func (q *Queries) Exists(name string, envid uint) bool {
	var count int64
	q.DB.Model(&DistributedQuery{}).Where("name = ? AND environment_id = ?", name, envid).Count(&count)
	return (count > 0)
}

// GetActive all active queries and carves by target
func (q *Queries) GetActive(envid uint) ([]DistributedQuery, error) {
	var queries []DistributedQuery
	if err := q.DB.Where("active = ? AND environment_id = ?", true, envid).Find(&queries).Error; err != nil {
		return queries, err
	}
	return queries, nil
}

// GetQueries all queries by target (active/completed/all/all-full/deleted/hidden)
func (q *Queries) GetQueries(target string, envid uint) ([]DistributedQuery, error) {
	return q.Gets(target, StandardQueryType, envid)
}

// GetCarves all carve queries by target (active/completed/all/all-full/deleted/hidden)
func (q *Queries) GetCarves(target string, envid uint) ([]DistributedQuery, error) {
	return q.Gets(target, CarveQueryType, envid)
}

// Get to get a query by name
func (q *Queries) Get(name string, envid uint) (DistributedQuery, error) {
	var query DistributedQuery
	if err := q.DB.Where("name = ? AND environment_id = ?", name, envid).Find(&query).Error; err != nil {
		return query, err
	}
	return query, nil
}

// GetNodeQueryTimestamps returns just the CreatedAt of every node_query row
// where this node was the target, since the cutoff. Used by the per-node
// activity heatmap.
//
// Pluck-style — drags only one column across the wire so the heatmap stays
// cheap when nodes have many tens of thousands of distributed queries.
func (q *Queries) GetNodeQueryTimestamps(nodeID uint, since time.Time) ([]time.Time, error) {
	var ts []time.Time
	err := q.DB.Model(&NodeQuery{}).
		Where("node_id = ? AND created_at >= ?", nodeID, since).
		Pluck("created_at", &ts).Error
	return ts, err
}

// GetNodeQueryBucketed returns per-bucket row counts for node_queries
// targeting `nodeID`, since `since`. Same bucketing semantics as the
// logging-package variants — see pkg/dbutil.BucketExpr for the dialect
// branching.
func (q *Queries) GetNodeQueryBucketed(nodeID uint, since time.Time, bucketSeconds int) ([]dbutil.BucketedRow, error) {
	expr := dbutil.BucketExpr(q.DB, "created_at", bucketSeconds)
	var rows []dbutil.BucketedRow
	err := q.DB.Model(&NodeQuery{}).
		Select(expr+" AS bucket_start, COUNT(*) AS cnt").
		Where("node_id = ? AND created_at >= ?", nodeID, since).
		Group("bucket_start").
		Scan(&rows).Error
	return rows, err
}

// Complete to mark query as completed
func (q *Queries) Complete(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
		return err
	}
	return nil
}

// Activate to mark query as active
func (q *Queries) Activate(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Updates(map[string]interface{}{"completed": false, "active": true}).Error; err != nil {
		return err
	}
	return nil
}

// Delete to mark query as deleted
func (q *Queries) Delete(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Updates(map[string]interface{}{"deleted": true, "active": false}).Error; err != nil {
		return err
	}
	return nil
}

// Expire to mark query/carve as expired
func (q *Queries) Expire(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Updates(map[string]interface{}{"expired": true, "active": false}).Error; err != nil {
		return err
	}

	// Mark all pending node queries for this distributed query as expired
	if err := q.SetNodeQueriesAsExpired(query.ID); err != nil {
		return err
	}
	return nil
}

// CleanupCompletedQueries to set all completed queries as inactive by environment
func (q *Queries) CleanupCompletedQueries(envid uint) error {
	qs, err := q.GetQueries(TargetActive, envid)
	if err != nil {
		return err
	}
	for _, query := range qs {
		executionReached := (query.Executions + query.Errors) >= query.Expected
		if executionReached {
			if err := q.DB.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupExpiredQueries to set all expired queries as inactive by environment
func (q *Queries) CleanupExpiredQueries(envid uint) error {
	qs, err := q.GetQueries(TargetActive, envid)
	if err != nil {
		return err
	}
	for _, query := range qs {
		if query.Expiration.Before(time.Now()) {
			if err := q.Expire(query.Name, envid); err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupExpiredCarves to set all expired carves as inactive by environment
func (q *Queries) CleanupExpiredCarves(envid uint) error {
	qs, err := q.GetCarves(TargetActive, envid)
	if err != nil {
		return err
	}
	for _, query := range qs {
		if query.Expiration.Before(time.Now()) {
			if err := q.Expire(query.Name, envid); err != nil {
				return err
			}
		}
	}
	return nil
}

// Create to create new query to be served to nodes
func (q *Queries) Create(query *DistributedQuery) error {
	if err := q.DB.Create(&query).Error; err != nil {
		return err
	}
	return nil
}

// CreateNodeQueries to link multiple nodes to a query
func (q *Queries) CreateNodeQueries(nodeIDs []uint, queryID uint) error {
	if len(nodeIDs) == 0 {
		return fmt.Errorf("no nodes to link to query")
	}
	var nodeQueries []NodeQuery
	for _, nodeID := range nodeIDs {
		nodeQueries = append(nodeQueries, NodeQuery{
			NodeID:  nodeID,
			QueryID: queryID,
		})
	}
	if err := q.DB.CreateInBatches(&nodeQueries, 1000).Error; err != nil {
		return err
	}
	return nil
}

// CreateTarget to create target entry for a given query
func (q *Queries) CreateTarget(name, targetType, targetValue string) error {
	queryTarget := DistributedQueryTarget{
		Name:  name,
		Type:  targetType,
		Value: targetValue,
	}
	if err := q.DB.Create(&queryTarget).Error; err != nil {
		return err
	}
	return nil
}

// GetTargets to retrieve targets for a given query
func (q *Queries) GetTargets(name string) ([]DistributedQueryTarget, error) {
	var targets []DistributedQueryTarget
	if err := q.DB.Where("name = ?", name).Find(&targets).Error; err != nil {
		return targets, err
	}
	return targets, nil
}

// IncExecution to increase the execution count for this query
func (q *Queries) IncExecution(name string, envid uint) error {
	result := q.DB.Model(&DistributedQuery{}).
		Where("name = ? AND environment_id = ?", name, envid).
		UpdateColumn("executions", gorm.Expr("executions + ?", 1))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("query %s not found for environment %d", name, envid)
	}
	return nil
}

// IncError to increase the error count for this query
func (q *Queries) IncError(name string, envid uint) error {
	result := q.DB.Model(&DistributedQuery{}).
		Where("name = ? AND environment_id = ?", name, envid).
		UpdateColumn("errors", gorm.Expr("errors + ?", 1))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("query %s not found for environment %d", name, envid)
	}
	return nil
}

// SetExpected to set the number of expected executions for this query
func (q *Queries) SetExpected(name string, expected int, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Update("expected", expected).Error; err != nil {
		return err
	}
	return nil
}

// UpdateQueryStatus to update the status of each query
func (q *Queries) UpdateQueryStatus(queryName string, nodeID uint, statusCode int) error {

	var result string
	if statusCode == 0 {
		result = DistributedQueryStatusCompleted
	} else {
		result = DistributedQueryStatusError
	}

	var query DistributedQuery
	// TODO: Get the query id
	// I think we can put an extra field in the query so that we also get the query id back from the osquery
	// This way we can avoid this query to get the query id
	if err := q.DB.Where("name = ?", queryName).Find(&query).Error; err != nil {
		return fmt.Errorf("error getting query id: %w", err)
	}

	var nodeQuery NodeQuery

	if err := q.DB.Where("node_id = ? AND query_id = ?", nodeID, query.ID).Find(&nodeQuery).Error; err != nil {
		return err
	}
	if err := q.DB.Model(&nodeQuery).Updates(map[string]interface{}{"status": result}).Error; err != nil {
		return err
	}

	var pending int64
	if err := q.DB.Model(&NodeQuery{}).
		Where("query_id = ? AND status = ?", query.ID, DistributedQueryStatusPending).
		Count(&pending).Error; err != nil {
		return err
	}
	// Standard distributed queries are complete once every targeted node has
	// reached a terminal node_query status. Carves use the same delivery
	// mechanism, but the actual file transfer continues after query delivery, so
	// they must not be auto-completed here.
	if pending == 0 && query.Type != CarveQueryType {
		if err := q.DB.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
			return err
		}
	}
	return nil
}

// SetNodeQueriesAsExpired marks all pending node queries for a specific distributed query as expired
func (q *Queries) SetNodeQueriesAsExpired(queryID uint) error {

	if err := q.DB.Model(&NodeQuery{}).
		Where("query_id = ? AND status = ?", queryID, DistributedQueryStatusPending).
		Updates(map[string]interface{}{"status": DistributedQueryStatusExpired}).Error; err != nil {
		return fmt.Errorf("error marking node queries as expired: %w", err)
	}

	return nil
}

// GetByEnvTargetPaged returns a page of queries for an env + target,
// with optional free-text search on name/creator/query, optional sort, and
// canonical pagination. qtype: StandardQueryType or CarveQueryType.
//
// page is 1-indexed. pageSize is clamped to [1, 500] with default 50.
func (q *Queries) GetByEnvTargetPaged(envID uint, target, qtype, search string, page, pageSize int, sortColumn string, desc bool) (QueryListPage, error) {
	if qtype == ConsoleQueryType {
		return QueryListPage{Items: []DistributedQuery{}}, nil
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	dbCol, ok := QuerySortableColumns[sortColumn]
	if !ok || sortColumn == "" {
		dbCol = "created_at"
		desc = true
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	orderExpr := fmt.Sprintf("%s %s", dbCol, dir)

	db := q.DB.Model(&DistributedQuery{}).Where("environment_id = ? AND type = ?", envID, qtype)
	// Apply the same target filtering as Gets():
	switch target {
	case TargetActive:
		db = db.Where("active = ? AND completed = ? AND deleted = ? AND expired = ?", true, false, false, false)
	case TargetCompleted:
		db = db.Where("active = ? AND completed = ? AND deleted = ? AND expired = ?", false, true, false, false)
	case TargetHiddenCompleted:
		db = db.Where("active = ? AND completed = ? AND deleted = ? AND hidden = ?", false, true, false, true)
	case TargetAllFull:
		db = db.Where("deleted = ?", false)
	case TargetAll:
		db = db.Where("deleted = ? AND hidden = ?", false, false)
	case TargetDeleted:
		db = db.Where("deleted = ?", true)
	case TargetHidden:
		db = db.Where("deleted = ? AND hidden = ?", false, true)
	case TargetExpired:
		db = db.Where("active = ? AND expired = ? AND deleted = ?", false, true, false)
	case TargetSaved:
		// Saved queries are not yet implemented as a separate table (Track 4 will).
		// Mirror Gets() semantics by returning zero rows here.
		db = db.Where("1 = 0")
	default:
		return QueryListPage{}, fmt.Errorf("invalid target %q", target)
	}

	if search != "" {
		like := "%" + search + "%"
		db = db.Where("name LIKE ? OR creator LIKE ? OR query LIKE ?", like, like, like)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return QueryListPage{}, err
	}
	var items []DistributedQuery
	if err := db.Order(orderExpr).Offset(offset).Limit(pageSize).Find(&items).Error; err != nil {
		return QueryListPage{}, err
	}
	return QueryListPage{Items: items, TotalItems: total}, nil
}
