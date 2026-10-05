package queries_test

import (
	"fmt"
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
		{ID: 1},
		{ID: 2},
		{ID: 3},
	}

	// Create test query
	testQuery := &queries.DistributedQuery{
		ID:            1,
		Name:          "test_query",
		Query:         "SELECT * FROM osquery_info;",
		Active:        true,
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

func TestNodeQueriesAcceleratesConsoleQueries(t *testing.T) {
	db := testDB(t)
	q, testNodes, _ := setupTestData(t, db)

	consoleQuery := queries.DistributedQuery{
		Name:          "console-query",
		Query:         "SELECT * FROM processes;",
		Type:          queries.ConsoleQueryType,
		Hidden:        true,
		Active:        true,
		EnvironmentID: 1,
		Expiration:    time.Now().Add(time.Hour),
	}
	require.NoError(t, q.Create(&consoleQuery))
	require.NoError(t, q.CreateNodeQueries([]uint{testNodes[0].ID}, consoleQuery.ID))

	result, accelerate, err := q.NodeQueries(testNodes[0])
	require.NoError(t, err)
	require.True(t, accelerate)
	require.Equal(t, "SELECT * FROM processes;", result["console-query"])

	otherResult, otherAccelerate, err := q.NodeQueries(testNodes[1])
	require.NoError(t, err)
	require.False(t, otherAccelerate)
	require.NotContains(t, otherResult, "console-query")
}

func TestNodeQueriesAcceleratesFileExplorerQueries(t *testing.T) {
	db := testDB(t)
	q, testNodes, _ := setupTestData(t, db)

	fileExplorerQuery := queries.DistributedQuery{
		Name:          "file-explorer-query",
		Query:         "select path from file where directory = '/'",
		Type:          queries.FileExplorerQueryType,
		Hidden:        true,
		Active:        true,
		EnvironmentID: 1,
		Expiration:    time.Now().Add(time.Hour),
	}
	require.NoError(t, q.Create(&fileExplorerQuery))
	require.NoError(t, q.CreateNodeQueries([]uint{testNodes[0].ID}, fileExplorerQuery.ID))

	result, accelerate, err := q.NodeQueries(testNodes[0])
	require.NoError(t, err)
	require.True(t, accelerate)
	require.Equal(t, "select path from file where directory = '/'", result["file-explorer-query"])
}

func TestNodeQueriesSkipsExpiredPendingQueries(t *testing.T) {
	db := testDB(t)
	q, testNodes, _ := setupTestData(t, db)

	expiredQuery := queries.DistributedQuery{
		Name:          "expired-console-query",
		Query:         "SELECT * FROM osquery_info;",
		Type:          queries.ConsoleQueryType,
		Hidden:        true,
		Active:        true,
		EnvironmentID: 1,
		Expiration:    time.Now().Add(-time.Minute),
	}
	require.NoError(t, q.Create(&expiredQuery))
	require.NoError(t, q.CreateNodeQueries([]uint{testNodes[0].ID}, expiredQuery.ID))

	result, accelerate, err := q.NodeQueries(testNodes[0])
	require.NoError(t, err)
	require.False(t, accelerate)
	require.NotContains(t, result, "expired-console-query")
}

func TestNodeQueriesReturnsNonExpiringPendingQueries(t *testing.T) {
	db := testDB(t)
	q, testNodes, _ := setupTestData(t, db)

	neverExpiresQuery := queries.DistributedQuery{
		Name:          "never-expires-query",
		Query:         "SELECT * FROM osquery_info;",
		Type:          queries.StandardQueryType,
		Active:        true,
		EnvironmentID: 1,
		Expiration:    time.Time{},
	}
	require.NoError(t, q.Create(&neverExpiresQuery))
	require.NoError(t, q.CreateNodeQueries([]uint{testNodes[0].ID}, neverExpiresQuery.ID))

	result, accelerate, err := q.NodeQueries(testNodes[0])
	require.NoError(t, err)
	require.False(t, accelerate)
	require.Equal(t, neverExpiresQuery.Query, result["never-expires-query"])
}

func TestCleanupExpiredQueriesKeepsNonExpiringQueriesActive(t *testing.T) {
	db := testDB(t)
	q, _, _ := setupTestData(t, db)

	neverExpiresQuery := queries.DistributedQuery{
		Name:          "never-expires-cleanup-query",
		Query:         "SELECT * FROM osquery_info;",
		Type:          queries.StandardQueryType,
		Active:        true,
		EnvironmentID: 1,
		Expiration:    time.Time{},
	}
	require.NoError(t, q.Create(&neverExpiresQuery))

	require.NoError(t, q.CleanupExpiredQueries(1))

	var reloaded queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", neverExpiresQuery.Name).First(&reloaded).Error)
	require.True(t, reloaded.Active)
	require.False(t, reloaded.Expired)
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

func TestUpdateQueryStatusCompletesParentQueryWhenAllTargetsFinish(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	relations := []queries.NodeQuery{
		{NodeID: nodes[0].ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending},
		{NodeID: nodes[1].ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending},
	}
	for _, relation := range relations {
		require.NoError(t, db.Create(&relation).Error)
	}

	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[0].ID, 0))

	var afterFirst queries.DistributedQuery
	require.NoError(t, db.First(&afterFirst, query.ID).Error)
	assert.False(t, afterFirst.Completed, "query should remain incomplete while one target is still pending")
	assert.True(t, afterFirst.Active, "query should remain active while one target is still pending")

	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[1].ID, 0))

	var afterSecond queries.DistributedQuery
	require.NoError(t, db.First(&afterSecond, query.ID).Error)
	assert.True(t, afterSecond.Completed, "query should be marked completed when all targets are terminal")
	assert.False(t, afterSecond.Active, "query should no longer be active when all targets are terminal")
}

func TestUpdateQueryStatusDoesNotAutoCompleteCarveWhenAllTargetsFinish(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)

	query.Type = queries.CarveQueryType
	query.Active = true
	query.Completed = false
	require.NoError(t, db.Save(&query).Error)

	relations := []queries.NodeQuery{
		{NodeID: nodes[0].ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending},
		{NodeID: nodes[1].ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending},
	}
	for _, relation := range relations {
		require.NoError(t, db.Create(&relation).Error)
	}

	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[0].ID, 0))
	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[1].ID, 0))

	var updated queries.DistributedQuery
	require.NoError(t, db.First(&updated, query.ID).Error)
	assert.False(t, updated.Completed, "carves should not be auto-completed when node query delivery finishes")
	assert.True(t, updated.Active, "carves should remain active until the carve flow itself is completed")
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
	assert.Equal(t, queries.DistributedQueryStatusPending, nodeQueries[0].Status, "First node query should be pending so tls/read can deliver it")
	assert.Equal(t, queries.DistributedQueryStatusPending, nodeQueries[1].Status, "Second node query should be pending so tls/read can deliver it")

	// Test error handling
	t.Run("EmptyNodeList", func(t *testing.T) {
		err := q.CreateNodeQueries([]uint{}, query.ID)
		assert.Error(t, err, "CreateNodeQueries should return an error with empty node list")
	})
}

func TestQuerySortableColumnsAllowlist(t *testing.T) {
	if _, ok := queries.QuerySortableColumns["unknown"]; ok {
		t.Error("unknown should not be allowed")
	}
	if _, ok := queries.QuerySortableColumns[""]; ok {
		t.Error("empty key should not be allowed")
	}
	if _, ok := queries.QuerySortableColumns["DROP TABLE"]; ok {
		t.Error("SQL fragment should not be allowed")
	}
	// Spot-check what the SPA depends on.
	if queries.QuerySortableColumns["name"] != "name" {
		t.Error("name → name")
	}
	if queries.QuerySortableColumns["created"] != "created_at" {
		t.Error("created → created_at")
	}
}

func TestConsoleQueriesAreExcludedFromNormalLists(t *testing.T) {
	db := testDB(t)
	q := queries.CreateQueries(db)

	envID := uint(1)
	normal := queries.DistributedQuery{
		Name:          "normal-query",
		Query:         "SELECT 1;",
		Type:          queries.StandardQueryType,
		EnvironmentID: envID,
		Active:        true,
	}
	consoleQuery := queries.DistributedQuery{
		Name:          "console-query",
		Query:         "SELECT * FROM file;",
		Type:          queries.ConsoleQueryType,
		EnvironmentID: envID,
		Active:        true,
		Hidden:        true,
	}
	require.NoError(t, q.Create(&normal))
	require.NoError(t, q.Create(&consoleQuery))

	items, err := q.GetQueries(queries.TargetAllFull, envID)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "normal-query", items[0].Name)

	hidden, err := q.GetQueries(queries.TargetHidden, envID)
	require.NoError(t, err)
	require.Empty(t, hidden)

	page, err := q.GetByEnvTargetPaged(envID, queries.TargetAllFull, queries.StandardQueryType, "", 1, 50, "created", true)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.TotalItems)
	require.Len(t, page.Items, 1)
	require.Equal(t, "normal-query", page.Items[0].Name)
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

// A node with no node_query row was never targeted. Reporting it is an error,
// and it must not touch the query's state or anyone else's status.
func TestUpdateQueryStatusRejectsUntargetedNode(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)
	require.NoError(t, db.Create(&queries.NodeQuery{NodeID: nodes[0].ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending}).Error)

	err := q.UpdateQueryStatus(query.Name, nodes[2].ID, 0)
	require.Error(t, err, "a node the query never targeted must be reported")

	var target queries.NodeQuery
	require.NoError(t, db.Where("node_id = ? AND query_id = ?", nodes[0].ID, query.ID).First(&target).Error)
	assert.Equal(t, queries.DistributedQueryStatusPending, target.Status, "the real target's status must be untouched")
	var unchanged queries.DistributedQuery
	require.NoError(t, db.First(&unchanged, query.ID).Error)
	assert.False(t, unchanged.Completed, "an untargeted report must not complete the query")
}

// An errored result is terminal too: the query completes once every target
// has either answered or failed.
func TestUpdateQueryStatusErrorsCountAsTerminal(t *testing.T) {
	db := testDB(t)
	q, nodes, query := setupTestData(t, db)
	for _, n := range nodes[:2] {
		require.NoError(t, db.Create(&queries.NodeQuery{NodeID: n.ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending}).Error)
	}

	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[0].ID, 1))
	require.NoError(t, q.UpdateQueryStatus(query.Name, nodes[1].ID, 0))

	var failed queries.NodeQuery
	require.NoError(t, db.Where("node_id = ? AND query_id = ?", nodes[0].ID, query.ID).First(&failed).Error)
	assert.Equal(t, queries.DistributedQueryStatusError, failed.Status)
	var done queries.DistributedQuery
	require.NoError(t, db.First(&done, query.ID).Error)
	assert.True(t, done.Completed, "a query whose targets all finished, one with an error, is complete")
}

// Completion looks for any remaining pending target rather than counting
// them. With many targets, the last pending row can sit behind every finished
// one; the query must stay open until exactly that row resolves.
func TestUpdateQueryStatusCompletesOnlyAfterLastPendingTarget(t *testing.T) {
	db := testDB(t)
	q := queries.CreateQueries(db)
	query := &queries.DistributedQuery{
		Name: "fanout", Query: "SELECT 1;", Active: true, EnvironmentID: 1,
		Expiration: time.Now().Add(time.Hour),
	}
	require.NoError(t, db.Create(query).Error)

	const targets = 40
	ids := make([]uint, targets)
	for i := range ids {
		n := nodes.OsqueryNode{UUID: fmt.Sprintf("NODE-%02d", i)}
		require.NoError(t, db.Create(&n).Error)
		ids[i] = n.ID
		require.NoError(t, db.Create(&queries.NodeQuery{NodeID: n.ID, QueryID: query.ID, Status: queries.DistributedQueryStatusPending}).Error)
	}

	// Answer in reverse insertion order, leaving the first-inserted row last.
	for i := targets - 1; i >= 1; i-- {
		require.NoError(t, q.UpdateQueryStatus(query.Name, ids[i], 0))
		var open queries.DistributedQuery
		require.NoError(t, db.First(&open, query.ID).Error)
		require.Falsef(t, open.Completed, "completed with %d target(s) still pending", i)
	}
	require.NoError(t, q.UpdateQueryStatus(query.Name, ids[0], 0))
	var done queries.DistributedQuery
	require.NoError(t, db.First(&done, query.ID).Error)
	assert.True(t, done.Completed, "query must complete when its last target answers")
	assert.False(t, done.Active)
}

// The grouped count must agree with GetQueries/GetCarves(TargetActive) for
// every environment, since StatsHandler swapped one for the other.
func TestActiveCountsByEnvironmentMatchesTargetActive(t *testing.T) {
	db := testDB(t)
	q := queries.CreateQueries(db)

	type spec struct {
		env                                 uint
		typ                                 string
		active, completed, deleted, expired bool
		hidden, softDeleted                 bool
	}
	specs := []spec{
		{env: 1, typ: queries.StandardQueryType, active: true},
		{env: 1, typ: queries.StandardQueryType, active: true, hidden: true}, // TargetActive does not filter hidden
		{env: 1, typ: queries.StandardQueryType, active: true, completed: true},
		{env: 1, typ: queries.StandardQueryType, active: true, deleted: true},
		{env: 1, typ: queries.StandardQueryType, active: true, expired: true},
		{env: 1, typ: queries.StandardQueryType, active: true, softDeleted: true},
		{env: 1, typ: queries.StandardQueryType},
		{env: 1, typ: queries.CarveQueryType, active: true},
		{env: 1, typ: queries.ConsoleQueryType, active: true},
		{env: 1, typ: queries.FileExplorerQueryType, active: true},
		{env: 2, typ: queries.CarveQueryType, active: true},
		{env: 2, typ: queries.CarveQueryType, active: true},
		{env: 3, typ: queries.StandardQueryType, completed: true},
	}
	for i, s := range specs {
		dq := queries.DistributedQuery{
			Name: fmt.Sprintf("q%02d", i), Query: "SELECT 1;", Type: s.typ, EnvironmentID: s.env,
			Active: s.active, Completed: s.completed, Deleted: s.deleted, Expired: s.expired, Hidden: s.hidden,
		}
		require.NoError(t, db.Create(&dq).Error)
		if s.softDeleted {
			require.NoError(t, db.Delete(&dq).Error)
		}
	}

	got, err := q.ActiveCountsByEnvironment()
	require.NoError(t, err)
	for _, env := range []uint{1, 2, 3, 4} {
		wantQ, err := q.GetQueries(queries.TargetActive, env)
		require.NoError(t, err)
		wantC, err := q.GetCarves(queries.TargetActive, env)
		require.NoError(t, err)
		assert.Equalf(t, queries.ActiveCounts{Queries: len(wantQ), Carves: len(wantC)}, got[env], "environment %d", env)
	}
	assert.Equal(t, queries.ActiveCounts{Queries: 2, Carves: 1}, got[1])
	assert.Equal(t, queries.ActiveCounts{Carves: 2}, got[2])
	_, hasEnv3 := got[3]
	assert.False(t, hasEnv3, "an environment with nothing active has no entry")
}
