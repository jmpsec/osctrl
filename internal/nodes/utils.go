package nodes

import (
	"math"
	"time"
)

// Helper to get what is the last seen time for a node
func IsActive(n OsqueryNode, inactive int64) bool {
	now := time.Now()
	// Check status if not empty/zero
	if !n.LastStatus.IsZero() {
		if n.LastStatus.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check result if not empty/zero
	if !n.LastResult.IsZero() {
		if n.LastResult.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check config if not empty/zero
	if !n.LastConfig.IsZero() {
		if n.LastConfig.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check query read if not empty/zero
	if !n.LastQueryRead.IsZero() {
		if n.LastQueryRead.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	// Check query write if not empty/zero
	if !n.LastQueryWrite.IsZero() {
		if n.LastQueryWrite.Sub(now).Hours() < math.Abs(float64(inactive)) {
			return true
		}
	}
	return false
}
