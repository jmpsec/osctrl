package main

import (
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// Helper to convert boolean to string
func stringifyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// Helper to get what is the last seen time for a node
func nodeLastSeen(n nodes.OsqueryNode) string {
	return utils.PastFutureTimes(n.LastSeen)

}
