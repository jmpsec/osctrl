package nodes

import (
	"fmt"
	"math"
	"time"
)

// Helper to get what is the last seen time for a node, inactive should be negative to check for past activity
func IsActive(n OsqueryNode, inactive int64) bool {
	now := time.Now()
	// Check status if not empty/zero
	if !n.LastStatus.IsZero() {
		if math.Abs(n.LastStatus.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check result if not empty/zero
	if !n.LastResult.IsZero() {
		if math.Abs(n.LastResult.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check config if not empty/zero
	if !n.LastConfig.IsZero() {
		if math.Abs(n.LastConfig.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check query read if not empty/zero
	if !n.LastQueryRead.IsZero() {
		if math.Abs(n.LastQueryRead.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check query write if not empty/zero
	if !n.LastQueryWrite.IsZero() {
		if math.Abs(n.LastQueryWrite.Sub(now).Hours()) < math.Abs(float64(inactive)) {
			return true
		}
	}
	return false
}

// Helper to generate the key to identify a node in the cache
func CacheKey(n OsqueryNode) string {
	return fmt.Sprintf("node:%d:%s", n.EnvironmentID, n.UUID)
}

// Helper to generate the key to identify last_seen events in the cache with the node
func CacheLastSeenKey(n OsqueryNode) string {
	return CacheLastSeenKeyStr(n.EnvironmentID, n.UUID)
}

// Helper to generate the key to identify last_seen events in the cache with the environment name and node UUID
func CacheLastSeenKeyStr(envID uint, uuid string) string {
	return fmt.Sprintf("last_seen:%d:%s", envID, uuid)
}

// Helper to convert the last seen time string stored in the cache to a time.Time object
func LastSeenTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// Helper to generate a key pattern by environment ID
func CacheLastSeenKeysEnv(envID uint) string {
	return fmt.Sprintf("last_seen:%d:*", envID)
}
