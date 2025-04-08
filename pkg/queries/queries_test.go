package queries_test

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// testDB creates an in-memory SQLite database for testing
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")

	// Initialize the tables
	q := queries.CreateQueries(db)
	require.NotNil(t, q, "Failed to create queries")

	n := nodes.CreateNodes(db)
	require.NotNil(t, n, "Failed to create nodes")

	return db
}

// setupTestData creates common test data for tests
func setupTestData(t *testing.T, db *gorm.DB) (*queries.Queries, []nodes.OsqueryNode, *queries.DistributedQuery) {
	t.Helper()

	// Create query service
	q := queries.CreateQueries(db)

	// Create test nodes
	testNodes := []nodes.OsqueryNode{
		{Model: gorm.Model{ID: 1}},
		{Model: gorm.Model{ID: 2}},
		{Model: gorm.Model{ID: 3}},
	}

	// Create test query
	testQuery := &queries.DistributedQuery{
		Model:         gorm.Model{ID: 1},
		Name:          "test_query",
		Query:         "SELECT * FROM osquery_info;",
		EnvironmentID: 1,
		Expiration:    time.Now().Add(24 * time.Hour),
	}

	// Save nodes to database
	for _, node := range testNodes {
		err := db.Create(&node).Error
		require.NoError(t, err, "Failed to create test node")
	}

	// Save query to database
	err := db.Create(testQuery).Error
	require.NoError(t, err, "Failed to create test distributed query")

	return q, testNodes, testQuery
}

func TestNodeQueries(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	// Create node query relationship
	nodeQuery := queries.NodeQuery{
		NodeID:  nodes[0].ID,
		QueryID: query.ID,
		Status:  queries.DistributedQueryStatusPending,
	}

	err := db.Create(&nodeQuery).Error
	require.NoError(t, err, "Failed to create test node query")

	// Test fetching queries for a node
	t.Run("RetrieveNodeQueries", func(t *testing.T) {
		result, _, err := q.NodeQueries(nodes[0])
		require.NoError(t, err, "NodeQueries should not return an error")

		assert.NotEmpty(t, result, "Expected non-empty queries")
		assert.Equal(t, query.Query, result[query.Name], "Query does not match expected value")
	})

	t.Run("NoQueriesForDifferentNode", func(t *testing.T) {
		result, _, err := q.NodeQueries(nodes[1])
		require.NoError(t, err, "NodeQueries should not return an error")

		assert.Empty(t, result, "Expected empty queries for node without assigned queries")
	})
}

func TestUpdateQueryStatus(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	// Test case table
	testCases := []struct {
		name       string
		nodeID     uint
		statusCode int
		expected   string
	}{
		{
			name:       "Complete with success",
			nodeID:     nodes[0].ID,
			statusCode: 0,
			expected:   queries.DistributedQueryStatusCompleted,
		},
		{
			name:       "Complete with error",
			nodeID:     nodes[1].ID,
			statusCode: 1,
			expected:   queries.DistributedQueryStatusError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create node query
			nodeQuery := queries.NodeQuery{
				NodeID:  tc.nodeID,
				QueryID: query.ID,
				Status:  queries.DistributedQueryStatusPending,
			}

			err := db.Create(&nodeQuery).Error
			require.NoError(t, err, "Failed to create test node query")

			// Update query status
			err = q.UpdateQueryStatus(query.Name, tc.nodeID, tc.statusCode)
			require.NoError(t, err, "UpdateQueryStatus should not return an error")

			// Verify status was updated
			var updatedNodeQuery queries.NodeQuery
			err = db.Where("node_id = ? AND query_id = ?", tc.nodeID, query.ID).Find(&updatedNodeQuery).Error
			require.NoError(t, err, "Failed to find updated node query")

			assert.Equal(t, tc.expected, updatedNodeQuery.Status, "Status does not match expected value")
		})
	}
}

func TestCreateNodeQueries(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	// Create node queries for multiple nodes
	nodeIDs := []uint{nodes[0].ID, nodes[1].ID}
	err := q.CreateNodeQueries(nodeIDs, query.ID)
	require.NoError(t, err, "CreateNodeQueries should not return an error")

	// Verify node queries were created
	var nodeQueries []queries.NodeQuery
	err = db.Where("query_id = ?", query.ID).Order("node_id").Find(&nodeQueries).Error
	require.NoError(t, err, "Failed to find created node queries")

	assert.Len(t, nodeQueries, 2, "Expected 2 node queries to be created")
	assert.Equal(t, nodeIDs[0], nodeQueries[0].NodeID, "First NodeID does not match expected value")
	assert.Equal(t, nodeIDs[1], nodeQueries[1].NodeID, "Second NodeID does not match expected value")

	// Test error handling
	t.Run("EmptyNodeList", func(t *testing.T) {
		err := q.CreateNodeQueries([]uint{}, query.ID)
		assert.Error(t, err, "CreateNodeQueries should return an error with empty node list")
	})
}

func TestSetNodeQueriesAsExpired(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	// Create node queries with different statuses
	nodeQueries := []queries.NodeQuery{
		{
			NodeID:  nodes[0].ID,
			QueryID: query.ID,
			Status:  queries.DistributedQueryStatusPending, // Should be updated to expired
		},
		{
			NodeID:  nodes[1].ID,
			QueryID: query.ID,
			Status:  queries.DistributedQueryStatusPending, // Should be updated to expired
		},
		{
			NodeID:  nodes[2].ID,
			QueryID: query.ID,
			Status:  queries.DistributedQueryStatusCompleted, // Should remain completed
		},
	}

	for _, nq := range nodeQueries {
		err := db.Create(&nq).Error
		require.NoError(t, err, "Failed to create test node query")
	}

	// Test the success case
	t.Run("SuccessCase", func(t *testing.T) {
		// Set pending node queries as expired
		err := q.SetNodeQueriesAsExpired(query.ID)
		require.NoError(t, err, "SetNodeQueriesAsExpired should not return an error")

		// Verify results
		var updatedNodeQueries []queries.NodeQuery
		err = db.Where("query_id = ?", query.ID).Order("node_id").Find(&updatedNodeQueries).Error
		require.NoError(t, err, "Failed to find updated node queries")

		require.Len(t, updatedNodeQueries, 3, "Expected 3 node queries")

		// Verify each node query status individually with clear descriptions
		t.Run("ExpirePendingNode1", func(t *testing.T) {
			assert.Equal(t, nodes[0].ID, updatedNodeQueries[0].NodeID)
			assert.Equal(t, queries.DistributedQueryStatusExpired, updatedNodeQueries[0].Status,
				"Node query with pending status should be updated to expired")
		})

		t.Run("ExpirePendingNode2", func(t *testing.T) {
			assert.Equal(t, nodes[1].ID, updatedNodeQueries[1].NodeID)
			assert.Equal(t, queries.DistributedQueryStatusExpired, updatedNodeQueries[1].Status,
				"Node query with pending status should be updated to expired")
		})

		t.Run("PreserveCompletedNode", func(t *testing.T) {
			assert.Equal(t, nodes[2].ID, updatedNodeQueries[2].NodeID)
			assert.Equal(t, queries.DistributedQueryStatusCompleted, updatedNodeQueries[2].Status,
				"Node query with completed status should remain completed")
		})
	})

	// Test with a non-existent query ID
	t.Run("NonExistentQueryID", func(t *testing.T) {
		nonExistentID := uint(999)
		err := q.SetNodeQueriesAsExpired(nonExistentID)

		// This should not return an error as it's a valid operation
		// that simply doesn't affect any rows
		assert.NoError(t, err, "SetNodeQueriesAsExpired should not return an error for non-existent query ID")

		// Verify no records were affected
		var count int64
		db.Model(&queries.NodeQuery{}).Where("status = ? AND query_id = ?",
			queries.DistributedQueryStatusExpired, nonExistentID).Count(&count)
		assert.Equal(t, int64(0), count, "No node queries should be marked as expired for a non-existent query ID")
	})

}
