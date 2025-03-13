package nodes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsActive(t *testing.T) {
	// Setup current time for reference
	now := time.Now()

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
				LastSeen: now.Add(-1 * time.Hour), // 1 hour ago
			},
			inactivity: 24, // 24 hours
			expected:   true,
		},
		{
			name: "Inactive node - seen too long ago",
			node: OsqueryNode{
				LastSeen: now.Add(-48 * time.Hour), // 48 hours ago
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
				LastSeen: now.Add(time.Duration(-24) * time.Hour), // 24 hours ago
			},
			inactivity: 24,    // 24 hours
			expected:   false, // Expected false due to the implementation checking for "less than" not "less than or equal"
		},
		{
			name: "Negative inactivity parameter",
			node: OsqueryNode{
				LastSeen: now.Add(-12 * time.Hour), // 12 hours ago
			},
			inactivity: -24, // -24 hours
			expected:   true,
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsActive(tt.node, tt.inactivity)
			if result != tt.expected {
				t.Errorf("IsActive() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCacheKey(t *testing.T) {
	node := OsqueryNode{
		EnvironmentID: 123,
		UUID:          "uuid",
	}
	assert.Equal(t, CacheKey(node), "node:123:uuid")
}

func TestCacheKeyRaw(t *testing.T) {
	assert.Equal(t, CacheKeyRaw("uuid", 123), "node:123:uuid")
}
