package queries

import (
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

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
)

// DistributedQuery as abstraction of a distributed query
type DistributedQuery struct {
	gorm.Model
	Name          string `gorm:"not null;unique;index"`
	Creator       string
	Query         string
	Expected      int
	Executions    int
	Errors        int
	Active        bool
	Hidden        bool
	Protected     bool
	Completed     bool
	Deleted       bool
	Expired       bool
	Type          string
	Path          string
	EnvironmentID uint
	ExtraData     string
	Expiration    time.Time
}

// NodeQuery links a node to a query
type NodeQuery struct {
	gorm.Model
	NodeID  uint   `gorm:"not null;index"`
	QueryID uint   `gorm:"not null;index"`
	Status  string `gorm:"type:varchar(8);default:'pending'"`
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
	//var q *Queries
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
	}

	q.DB.Table("distributed_queries dq").
		Select("dq.name, dq.query").
		Joins("JOIN node_queries nq ON dq.id = nq.query_id").
		Where("nq.node_id = ? AND nq.status = ?", node.ID, DistributedQueryStatusPending).
		Scan(&results)

	if len(results) == 0 {
		return QueryReadQueries{}, false, nil
	}

	qs := make(QueryReadQueries)
	for _, _q := range results {
		qs[_q.Name] = _q.Query
	}

	return qs, false, nil
}

// Gets all queries by target (active/completed/all/all-full/deleted/hidden/expired)
func (q *Queries) Gets(target, qtype string, envid uint) ([]DistributedQuery, error) {
	var queries []DistributedQuery
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
func (q *Queries) Create(query DistributedQuery) error {
	if err := q.DB.Create(&query).Error; err != nil {
		return err
	}
	return nil
}

// CreateNodeQuery to link a node to a query
func (q *Queries) CreateNodeQuery(nodeID, queryID uint) error {
	nodeQuery := NodeQuery{
		NodeID:  nodeID,
		QueryID: queryID,
	}
	if err := q.DB.Create(&nodeQuery).Error; err != nil {
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
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Update("executions", query.Executions+1).Error; err != nil {
		return err
	}
	return nil
}

// IncError to increase the error count for this query
func (q *Queries) IncError(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if err := q.DB.Model(&query).Update("errors", query.Errors+1).Error; err != nil {
		return err
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
		return fmt.Errorf("error getting query id: %v", err)
	}

	var nodeQuery NodeQuery

	if err := q.DB.Where("node_id = ? AND query_id = ?", nodeID, query.ID).Find(&nodeQuery).Error; err != nil {
		return err
	}
	if err := q.DB.Model(&nodeQuery).Updates(map[string]interface{}{"status": result}).Error; err != nil {
		return err
	}
	return nil
}
