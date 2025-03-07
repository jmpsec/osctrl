package nodes

import (
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
