package nodes

import (
	"math"
	"time"
)

// Helper to get what is the last seen time for a node, inactive should be negative to check for past activity
func IsActive(n OsqueryNode, inactive int64) bool {
	now := time.Now()
	// Check config if not empty/zero
	if !n.LastSeen.IsZero() {
		if n.LastSeen.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	return false
}
