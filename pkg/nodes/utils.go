package nodes

import (
	"fmt"
	"math"
	"time"
)

// Helper to get what is the last seen time for a node, inactive should be negative to check for past activity
func IsActive(n OsqueryNode, inactive int64) bool {
	now := time.Now()
	// Check config if not empty/zero
	if !n.LastSeen.IsZero() {
		if math.Abs(n.LastSeen.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	return false
}

// Helper to generate the key to identify a full node in the cache, by UUID
func CacheFullKeyByUUID(n OsqueryNode) string {
	return CacheFullKeyRaw(n.UUID, n.EnvironmentID)
}

// Helper to generate the key to identify a full node in the cache, by node_key
func CacheFullKeyByNodeKey(n OsqueryNode) string {
	return CacheFullKeyRaw(n.NodeKey, n.EnvironmentID)
}

// Helper to generate the key to identify a full node in the cache
func CacheFullKeyRaw(identifier string, envID uint) string {
	return fmt.Sprintf("fullnode:%d:%s", envID, identifier)
}

// Helper to generate the key to identify partially node in the cache, by UUID
func CachePartialKeyByUUID(n OsqueryNode) string {
	return CachePartialKeyRaw(n.UUID, n.EnvironmentID)
}

// Helper to generate the key to identify partially node in the cache, by node_key
func CachePartialKeyByNodeKey(n OsqueryNode) string {
	return CachePartialKeyRaw(n.NodeKey, n.EnvironmentID)
}

// Helper to generate the key to identify partially node in the cache
func CachePartialKeyRaw(identifier string, envID uint) string {
	return fmt.Sprintf("partialnode:%d:%s", envID, identifier)
}
