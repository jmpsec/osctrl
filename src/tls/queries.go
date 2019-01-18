package main

import "fmt"

const (
	queryTargetPlatform  string = "platform"
	queryTargetLocalname string = "localname"
	queryTargetContext   string = "context"
	queryTargetUUID      string = "uuid"
)

// Get all queries that belong to the provided node_key
// FIXME this will impact the performance of the TLS endpoint due to being CPU and I/O hungry
// FIMXE potential mitigation can be add a cache (Redis?) layer to store queries per node_key
func getQueriesForNode(nodeKey string) (QueryReadQueries, error) {
	// Retrieve node
	node, err := getNodeByKey(nodeKey)
	if err != nil {
		return QueryReadQueries{}, err
	}
	// Get all current active queries
	queries, err := getQueries("active")
	if err != nil {
		return QueryReadQueries{}, err
	}
	// Iterate through active queries, see if they target this node and prepare data in the same loop
	qs := make(QueryReadQueries)
	for _, q := range queries {
		targets, err := getQueryTargets(q.Name)
		if err != nil {
			return QueryReadQueries{}, err
		}
		if isQueryTarget(node, targets) && queryNotYetExecuted(q.Name, node.UUID) {
			qs[q.Name] = q.Query
		}
	}
	return qs, nil
}

// Get all queries by target (active/completed)
func getQueries(target string) ([]DistributedQuery, error) {
	var queries []DistributedQuery
	switch target {
	case "active":
		if err := db.Where("active = ? AND completed = ? AND deleted = ?", true, false, false).Find(&queries).Error; err != nil {
			return queries, err
		}
	case "completed":
		if err := db.Where("active = ? AND completed = ? AND deleted = ?", false, true, false).Find(&queries).Error; err != nil {
			return queries, err
		}
	}
	return queries, nil
}

// Get query by name
func getQuery(name string) (DistributedQuery, error) {
	var query DistributedQuery
	if err := db.Where("name = ?", name).Find(&query).Error; err != nil {
		return query, err
	}
	return query, nil
}

// Mark query as completed
func completeQuery(name string) error {
	query, err := getQuery(name)
	if err != nil {
		return err
	}
	if err := db.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
		return err
	}
	return nil
}

// Mark query as active
func activateQuery(name string) error {
	query, err := getQuery(name)
	if err != nil {
		return err
	}
	if err := db.Model(&query).Updates(map[string]interface{}{"completed": false, "active": true}).Error; err != nil {
		return err
	}
	return nil
}

// Mark query as deleted
func deleteQuery(name string) error {
	query, err := getQuery(name)
	if err != nil {
		return err
	}
	if err := db.Model(&query).Updates(map[string]interface{}{"deleted": true, "active": false}).Error; err != nil {
		return err
	}
	return nil
}

// Create new query to be served to nodes
func createQuery(query DistributedQuery) error {
	if db.NewRecord(query) {
		if err := db.Create(&query).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Create target entry for a given query
func createQueryTarget(name, targetType, targetValue string) error {
	queryTarget := DistributedQueryTarget{
		Name:  name,
		Type:  targetType,
		Value: targetValue,
	}
	if db.NewRecord(queryTarget) {
		if err := db.Create(&queryTarget).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Retrieve targets for a given query
func getQueryTargets(name string) ([]DistributedQueryTarget, error) {
	var targets []DistributedQueryTarget
	if err := db.Where("name = ?", name).Find(&targets).Error; err != nil {
		return targets, err
	}
	return targets, nil
}

// Check if query already executed or it is within the interval
func queryNotYetExecuted(name, uuid string) bool {
	var results int
	db.Model(&DistributedQueryExecution{}).Where("name = ? AND uuid = ?", name, uuid).Count(&results)
	return (results == 0)
}

// Increase the execution count for this query
func incQueryExecution(name string) error {
	query, err := getQuery(name)
	if err != nil {
		return err
	}
	if err := db.Model(&query).Update("executions", query.Executions+1).Error; err != nil {
		return err
	}
	return nil
}

// Increase the error count for this query
func incQueryError(name string) error {
	query, err := getQuery(name)
	if err != nil {
		return err
	}
	if err := db.Model(&query).Update("errors", query.Errors+1).Error; err != nil {
		return err
	}
	return nil
}

// Keep track of where queries have already ran
func trackQueryExecution(name, uuid string, result int) error {
	queryExecution := DistributedQueryExecution{
		Name:   name,
		UUID:   uuid,
		Result: result,
	}
	if db.NewRecord(queryExecution) {
		if err := db.Create(&queryExecution).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}
