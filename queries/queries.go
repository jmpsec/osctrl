package queries

import (
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
	// TargetSaved for saved queries
	TargetSaved string = "saved"
	// TargetHiddenCompleted for hidden completed queries
	TargetHiddenCompleted string = "hidden-completed"
	// TargetDeleted for deleted queries
	TargetDeleted string = "deleted"
	// TargetHidden for hidden queries
	TargetHidden string = "hidden"
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
	Type          string
	Path          string
	EnvironmentID uint
	ExtraData     string
}

// DistributedQueryTarget to keep target logic for queries
type DistributedQueryTarget struct {
	gorm.Model
	Name  string `gorm:"index"`
	Type  string
	Value string
}

// DistributedQueryExecution to keep track of queries executing
type DistributedQueryExecution struct {
	gorm.Model
	Name   string `gorm:"index"`
	UUID   string `gorm:"index"`
	Result int
}

// QueryReadQueries to hold all the on-demand queries
type QueryReadQueries map[string]string

// Queries to handle on-demand queries
type Queries struct {
	DB *gorm.DB
}

// CreateQueries to initialize the queries struct
func CreateQueries(backend *gorm.DB) *Queries {
	var q *Queries
	q = &Queries{DB: backend}
	// table distributed_queries
	if err := backend.AutoMigrate(&DistributedQuery{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (distributed_queries): %v", err)
	}
	// table distributed_query_executions
	if err := backend.AutoMigrate(&DistributedQueryExecution{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (distributed_query_executions): %v", err)
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

// NodeQueries to get all queries that belong to the provided node
// FIXME this will impact the performance of the TLS endpoint due to being CPU and I/O hungry
// FIMXE potential mitigation can be add a cache (Redis?) layer to store queries per node_key
func (q *Queries) NodeQueries(node nodes.OsqueryNode) (QueryReadQueries, bool, error) {
	acelerate := false
	// Get all current active queries and carves
	queries, err := q.GetActive(node.EnvironmentID)
	if err != nil {
		return QueryReadQueries{}, false, err
	}
	// Iterate through active queries, see if they target this node and prepare data in the same loop
	qs := make(QueryReadQueries)
	for _, _q := range queries {
		targets, err := q.GetTargets(_q.Name)
		if err != nil {
			return QueryReadQueries{}, false, err
		}
		// FIXME disable acceleration until figure out edge cases where it would trigger by mistake
		/*
			if len(targets) == 1 {
				acelerate = true
			}
		*/
		if isQueryTarget(node, targets) && q.NotYetExecuted(_q.Name, node.UUID) {
			qs[_q.Name] = _q.Query
		}
	}
	return qs, acelerate, nil
}

// Gets all queries by target (active/completed/all/all-full/deleted/hidden)
func (q *Queries) Gets(target, qtype string, envid uint) ([]DistributedQuery, error) {
	var queries []DistributedQuery
	switch target {
	case TargetActive:
		if err := q.DB.Where(
			"active = ? AND completed = ? AND deleted = ? AND type = ? AND environment_id = ?",
			true,
			false,
			false,
			qtype,
			envid,
		).Find(&queries).Error; err != nil {
			return queries, err
		}
	case TargetCompleted:
		if err := q.DB.Where(
			"active = ? AND completed = ? AND deleted = ? AND type = ? AND environment_id = ?",
			false,
			true,
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
	}
	return queries, nil
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

// VerifyComplete to mark query as completed if the expected executions are done
func (q *Queries) VerifyComplete(name string, envid uint) error {
	query, err := q.Get(name, envid)
	if err != nil {
		return err
	}
	if (query.Executions + query.Errors) >= query.Expected {
		if err := q.DB.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
			return err
		}
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

// Create to create new query to be served to nodes
func (q *Queries) Create(query DistributedQuery) error {
	if err := q.DB.Create(&query).Error; err != nil {
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

// NotYetExecuted to check if query already executed or it is within the interval
func (q *Queries) NotYetExecuted(name, uuid string) bool {
	var results int64
	q.DB.Model(&DistributedQueryExecution{}).Where("name = ? AND uuid = ?", name, uuid).Count(&results)
	return (results == 0)
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

// TrackExecution to keep track of where queries have already ran
func (q *Queries) TrackExecution(name, uuid string, result int) error {
	queryExecution := DistributedQueryExecution{
		Name:   name,
		UUID:   uuid,
		Result: result,
	}
	if err := q.DB.Create(&queryExecution).Error; err != nil {
		return err
	}
	return nil
}

// Helper to decide whether if the query targets apply to a give node
func isQueryTarget(node nodes.OsqueryNode, targets []DistributedQueryTarget) bool {
	for _, t := range targets {
		// Check for environment match
		if t.Type == QueryTargetEnvironment && t.Value == node.Environment {
			return true
		}
		// Check for platform match
		if t.Type == QueryTargetPlatform && node.Platform == t.Value {
			return true
		}
		// Check for UUID match
		if t.Type == QueryTargetUUID && node.UUID == t.Value {
			return true
		}
		// Check for localname match
		if t.Type == QueryTargetLocalname && node.Localname == t.Value {
			return true
		}
	}
	return false
}
