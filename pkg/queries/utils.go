package queries

import (
	"github.com/javuto/osctrl/pkg/nodes"
)

// Helper to decide whether if the query targets apply to a give node
func isQueryTarget(node nodes.OsqueryNode, targets []DistributedQueryTarget) bool {
	for _, t := range targets {
		// Check for environment match
		if t.Type == QueryTargetEnvironment && t.Value == node.Environment {
			return true
		}
		// Check for platform match
		if t.Type == QueryTargetPlatform && node.Platform == t.Value {
			return true
		}
		// Check for UUID match
		if t.Type == QueryTargetUUID && node.UUID == t.Value {
			return true
		}
		// Check for localname match
		if t.Type == QueryTargetLocalname && node.Localname == t.Value {
			return true
		}
	}
	return false
}
