package queries_test

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func TestNodeQueries(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	// Create tables
	q := queries.CreateQueries(db)
	nodes.CreateNodes(db)

	// Create test data
	node := nodes.OsqueryNode{
		Model: gorm.Model{ID: 1},
	}
	distributedQuery := queries.DistributedQuery{
		Model:         gorm.Model{ID: 1},
		Name:          "test_query",
		Query:         "SELECT * FROM osquery_info;",
		EnvironmentID: 1,
		Expiration:    time.Now().Add(24 * time.Hour),
	}
	nodeQuery := queries.NodeQuery{
		NodeID:  1,
		QueryID: 1,
		Status:  queries.DistributedQueryStatusPending,
	}

	// Query sqlite_master to list all tables
	var tables []string
	err = db.Raw("SELECT name FROM sqlite_master WHERE type='table'").Scan(&tables).Error
	if err != nil {
		log.Fatalf("failed to list tables: %v", err)
	}

	fmt.Println("Tables in the database:")
	for _, table := range tables {
		fmt.Println(table)
	}

	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("Failed to create test node: %v", err)
	}
	if err := db.Create(&distributedQuery).Error; err != nil {
		t.Fatalf("Failed to create test distributed query: %v", err)
	}
	if err := db.Create(&nodeQuery).Error; err != nil {
		t.Fatalf("Failed to create test node query: %v", err)
	}

	// Test NodeQueries function
	queries, _, err := q.NodeQueries(node)
	if err != nil {
		t.Fatalf("NodeQueries returned an error: %v", err)
	}
	// Print queries
	fmt.Println(queries)

	assert.NotEmpty(t, queries, "Expected non-empty queries")
	assert.Equal(t, "SELECT * FROM osquery_info;", queries["test_query"], "Query does not match expected value")
}
func TestUpdateQueryStatus(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	// Create tables
	q := queries.CreateQueries(db)
	nodes.CreateNodes(db)

	// Create test data
	node := nodes.OsqueryNode{
		Model: gorm.Model{ID: 1},
	}
	distributedQuery := queries.DistributedQuery{
		Model:         gorm.Model{ID: 1},
		Name:          "test_query",
		Query:         "SELECT * FROM osquery_info;",
		EnvironmentID: 1,
		Expiration:    time.Now().Add(24 * time.Hour),
	}
	nodeQuery := queries.NodeQuery{
		NodeID:  1,
		QueryID: 1,
		Status:  queries.DistributedQueryStatusPending,
	}

	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("Failed to create test node: %v", err)
	}
	if err := db.Create(&distributedQuery).Error; err != nil {
		t.Fatalf("Failed to create test distributed query: %v", err)
	}
	if err := db.Create(&nodeQuery).Error; err != nil {
		t.Fatalf("Failed to create test node query: %v", err)
	}

	// Test UpdateQueryStatus function
	err = q.UpdateQueryStatus("test_query", 1, 0)
	if err != nil {
		t.Fatalf("UpdateQueryStatus returned an error: %v", err)
	}

	var updatedNodeQuery queries.NodeQuery
	if err := db.Where("node_id = ? AND query_id = ?", 1, 1).Find(&updatedNodeQuery).Error; err != nil {
		t.Fatalf("Failed to find updated node query: %v", err)
	}

	assert.Equal(t, queries.DistributedQueryStatusCompleted, updatedNodeQuery.Status, "Status does not match expected value")
}

func TestCreateNodeQueries(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	// Create tables
	q := queries.CreateQueries(db)
	nodes.CreateNodes(db)

	// Create test data
	node1 := nodes.OsqueryNode{
		Model: gorm.Model{ID: 1},
	}
	node2 := nodes.OsqueryNode{
		Model: gorm.Model{ID: 2},
	}
	distributedQuery := queries.DistributedQuery{
		Model:         gorm.Model{ID: 1},
		Name:          "test_query",
		Query:         "SELECT * FROM osquery_info;",
		EnvironmentID: 1,
		Expiration:    time.Now().Add(24 * time.Hour),
	}

	if err := db.Create(&node1).Error; err != nil {
		t.Fatalf("Failed to create test node1: %v", err)
	}
	if err := db.Create(&node2).Error; err != nil {
		t.Fatalf("Failed to create test node2: %v", err)
	}
	if err := db.Create(&distributedQuery).Error; err != nil {
		t.Fatalf("Failed to create test distributed query: %v", err)
	}

	// Test CreateNodeQueries function
	nodeIDs := []uint{1, 2}
	err = q.CreateNodeQueries(nodeIDs, 1)
	if err != nil {
		t.Fatalf("CreateNodeQueries returned an error: %v", err)
	}

	var nodeQueries []queries.NodeQuery
	if err := db.Where("query_id = ?", 1).Find(&nodeQueries).Error; err != nil {
		t.Fatalf("Failed to find created node queries: %v", err)
	}

	assert.Len(t, nodeQueries, 2, "Expected 2 node queries to be created")
	assert.Equal(t, uint(1), nodeQueries[0].NodeID, "First NodeID does not match expected value")
	assert.Equal(t, uint(1), nodeQueries[0].QueryID, "First QueryID does not match expected value")
	assert.Equal(t, uint(2), nodeQueries[1].NodeID, "Second NodeID does not match expected value")
	assert.Equal(t, uint(1), nodeQueries[1].QueryID, "Second QueryID does not match expected value")
}
