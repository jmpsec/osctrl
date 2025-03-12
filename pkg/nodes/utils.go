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

// Helper to generate the key to identify a node in the cache
func CacheKey(n OsqueryNode) string {
	return CacheKeyRaw(n.UUID, n.EnvironmentID)
}

// Helper to generate the key to identify a node in the cache
func CacheKeyRaw(uuid string, envID uint) string {
	return fmt.Sprintf("node:%d:%s", envID, uuid)
}
