package nodes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")

	// Migrate the schema
	err = db.AutoMigrate(&OsqueryNode{})
	require.NoError(t, err, "Failed to migrate schema")

	return db
}

// testNodeParams defines optional parameters for creating mock nodes
type testNodeParams struct {
	UUID        string
	Hostname    string
	Platform    string
	LastSeen    time.Time
	Environment string
	Username    string
	OsqueryUser string
	Version     string
}

// createMockNode creates a test node with the given parameters
// It accepts optional parameters to customize the node
func createMockNode(db *gorm.DB, params testNodeParams) OsqueryNode {
	if params.UUID == "" {
		params.UUID = "TEST-UUID"
	}

	if params.Hostname == "" {
		params.Hostname = "test-host"
	}

	if params.Platform == "" {
		params.Platform = "darwin"
	}

	node := OsqueryNode{
		UUID:            params.UUID,
		Hostname:        params.Hostname,
		Platform:        params.Platform,
		LastSeen:        params.LastSeen,
		Environment:     params.Environment,
		Username:        params.Username,
		OsqueryUser:     params.OsqueryUser,
		PlatformVersion: params.Version,
	}

	db.Create(&node)
	return node
}

func TestIsActive(t *testing.T) {
	// Use a fixed reference time for deterministic tests
	refTime := time.Date(2025, 4, 10, 12, 0, 0, 0, time.UTC)

	// Test cases
	tests := []struct {
		name       string
		node       OsqueryNode
		inactivity int64
		expected   bool
	}{
		{
			name: "Active node - recently seen",
			node: OsqueryNode{
				LastSeen: refTime.Add(-1 * time.Hour), // 1 hour ago
			},
			inactivity: 24, // 24 hours
			expected:   true,
		},
		{
			name: "Inactive node - seen too long ago",
			node: OsqueryNode{
				LastSeen: refTime.Add(-48 * time.Hour), // 48 hours ago
			},
			inactivity: 24, // 24 hours
			expected:   false,
		},
		{
			name: "Node with zero time - should be inactive",
			node: OsqueryNode{
				LastSeen: time.Time{}, // Zero time
			},
			inactivity: 24,
			expected:   false,
		},
		{
			name: "Edge case - seen exactly at inactivity threshold",
			node: OsqueryNode{
				LastSeen: refTime.Add(-24 * time.Hour), // 24 hours ago
			},
			inactivity: 24,    // 24 hours
			expected:   false, // Should be inactive because it's not after the cutoff
		},
		{
			name: "Negative inactivity parameter",
			node: OsqueryNode{
				LastSeen: refTime.Add(-12 * time.Hour), // 12 hours ago
			},
			inactivity: -24,   // -24 hours (moves cutoff into the future)
			expected:   false, // Should be inactive with negative inactivity
		},
	}

	// Mock time.Now() to return our reference time
	originalTimeNow := timeNow
	timeNow = func() time.Time { return refTime }
	defer func() { timeNow = originalTimeNow }() // restore the original function

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsActive(tt.node, tt.inactivity)
			assert.Equal(t, tt.expected, result, "IsActive() returned unexpected result")
		})
	}
}

func TestActiveTimeCutoff(t *testing.T) {
	// Use a fixed reference time for deterministic tests
	refTime := time.Date(2025, 4, 10, 12, 0, 0, 0, time.UTC)

	// Mock time.Now() to return our reference time
	originalTimeNow := timeNow
	timeNow = func() time.Time { return refTime }
	defer func() { timeNow = originalTimeNow }() // restore the original function

	tests := []struct {
		name     string
		hours    int64
		expected time.Time
	}{
		{
			name:     "24 hours cutoff",
			hours:    24,
			expected: refTime.Add(-24 * time.Hour),
		},
		{
			name:     "Zero hours cutoff",
			hours:    0,
			expected: refTime,
		},
		{
			name:     "Negative hours cutoff",
			hours:    -10,
			expected: refTime.Add(10 * time.Hour), // Future time
		},
		{
			name:     "Large hours cutoff",
			hours:    720, // 30 days
			expected: refTime.Add(-720 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cutoff := ActiveTimeCutoff(tt.hours)
			assert.Equal(t, tt.expected, cutoff, "ActiveTimeCutoff() returned unexpected time")
		})
	}
}

func TestApplyNodeTarget(t *testing.T) {
	db := setupTestDB(t)

	// Use a fixed reference time for deterministic tests
	refTime := time.Date(2025, 4, 10, 12, 0, 0, 0, time.UTC)

	// Mock time.Now() to return our reference time
	originalTimeNow := timeNow
	timeNow = func() time.Time { return refTime }
	defer func() { timeNow = originalTimeNow }() // restore the original function

	// Create sample nodes with different last seen times
	activeNode := createMockNode(db, testNodeParams{
		LastSeen: refTime.Add(-1 * time.Hour), // 1 hour ago
	})
	inactiveNode := createMockNode(db, testNodeParams{
		UUID:     "INACTIVE-UUID",
		LastSeen: refTime.Add(-48 * time.Hour), // 48 hours ago
	})

	// Define test cases
	tests := []struct {
		name            string
		target          string
		hours           int64
		expectedNodeIDs []uint
	}{
		{
			name:            "All nodes target",
			target:          AllNodes,
			hours:           24,
			expectedNodeIDs: []uint{activeNode.ID, inactiveNode.ID},
		},
		{
			name:            "Active nodes target",
			target:          ActiveNodes,
			hours:           24,
			expectedNodeIDs: []uint{activeNode.ID},
		},
		{
			name:            "Inactive nodes target",
			target:          InactiveNodes,
			hours:           24,
			expectedNodeIDs: []uint{inactiveNode.ID},
		},
		{
			name:            "Invalid target defaults to all nodes",
			target:          "invalid-target",
			hours:           24,
			expectedNodeIDs: []uint{activeNode.ID, inactiveNode.ID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodes []OsqueryNode

			// Apply the node target filter
			query := db.Model(&OsqueryNode{})
			result := ApplyNodeTarget(query, tt.target, tt.hours)

			// Execute the query
			err := result.Find(&nodes).Error
			require.NoError(t, err, "Failed to execute the filtered query")

			// Extract the IDs for comparison
			var actualNodeIDs []uint
			for _, n := range nodes {
				actualNodeIDs = append(actualNodeIDs, n.ID)
			}

			assert.ElementsMatch(t, tt.expectedNodeIDs, actualNodeIDs, "Filtered nodes don't match expected IDs")
		})
	}
}

func TestGetStats(t *testing.T) {
	db := setupTestDB(t)

	// Use a fixed reference time for deterministic tests
	refTime := time.Date(2025, 4, 10, 12, 0, 0, 0, time.UTC)

	// Mock time.Now() to return our reference time
	originalTimeNow := timeNow
	timeNow = func() time.Time { return refTime }
	defer func() { timeNow = originalTimeNow }() // restore the original function

	// Clear database to ensure clean state
	db.Exec("DELETE FROM osquery_nodes")

	// Create test nodes with different environments and platforms using the enhanced createMockNode

	// Platform: darwin - 2 active, 1 inactive
	createMockNode(db, testNodeParams{
		UUID:     "ACTIVE-DARWIN-1",
		Platform: "darwin",
		LastSeen: refTime.Add(-1 * time.Hour), // 1 hour ago (active)
	})

	createMockNode(db, testNodeParams{
		UUID:        "ACTIVE-DARWIN-2",
		Platform:    "darwin",
		Environment: "prod",
		LastSeen:    refTime.Add(-2 * time.Hour), // 2 hours ago (active)
	})

	createMockNode(db, testNodeParams{
		UUID:        "INACTIVE-DARWIN-1",
		Platform:    "darwin",
		Environment: "prod",
		LastSeen:    refTime.Add(-48 * time.Hour), // 48 hours ago (inactive)
	})

	// Platform: windows - 1 active, 2 inactive
	createMockNode(db, testNodeParams{
		UUID:        "ACTIVE-WINDOWS-1",
		Platform:    "windows",
		Environment: "dev",
		LastSeen:    refTime.Add(-6 * time.Hour), // 6 hours ago (active)
	})

	createMockNode(db, testNodeParams{
		UUID:        "INACTIVE-WINDOWS-1",
		Platform:    "windows",
		Environment: "dev",
		LastSeen:    refTime.Add(-48 * time.Hour), // 48 hours ago (inactive)
	})

	createMockNode(db, testNodeParams{
		UUID:        "INACTIVE-WINDOWS-2",
		Platform:    "windows",
		Environment: "dev",
		LastSeen:    refTime.Add(-72 * time.Hour), // 72 hours ago (inactive)
		Username:    "test-user",
	})

	// Verify our test setup
	var count int64
	db.Model(&OsqueryNode{}).Count(&count)
	require.Equal(t, int64(6), count, "Should have 6 test nodes in database")

	// Test cases
	tests := []struct {
		name          string
		column        string
		value         string
		hours         int64
		expectedStats StatsData
	}{
		{
			name:   "Stats for darwin platform",
			column: "platform",
			value:  "darwin",
			hours:  24,
			expectedStats: StatsData{
				Total:    3,
				Active:   2,
				Inactive: 1,
			},
		},
		{
			name:   "Stats for windows platform",
			column: "platform",
			value:  "windows",
			hours:  24,
			expectedStats: StatsData{
				Total:    3,
				Active:   1,
				Inactive: 2,
			},
		},
		{
			name:   "Stats for prod environment",
			column: "environment",
			value:  "prod",
			hours:  24,
			expectedStats: StatsData{
				Total:    2,
				Active:   1,
				Inactive: 1,
			},
		},
		{
			name:   "Stats for dev environment",
			column: "environment",
			value:  "dev",
			hours:  24,
			expectedStats: StatsData{
				Total:    3,
				Active:   1,
				Inactive: 2,
			},
		},
		{
			name:   "Stats for non-existent value",
			column: "platform",
			value:  "linux",
			hours:  24,
			expectedStats: StatsData{
				Total:    0,
				Active:   0,
				Inactive: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := GetStats(db, tt.column, tt.value, tt.hours)
			require.NoError(t, err, "GetStats should not return an error")

			assert.Equal(t, tt.expectedStats.Total, stats.Total, "Total count mismatch")
			assert.Equal(t, tt.expectedStats.Active, stats.Active, "Active count mismatch")
			assert.Equal(t, tt.expectedStats.Inactive, stats.Inactive, "Inactive count mismatch")
		})
	}
}
