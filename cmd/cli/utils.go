package main

import (
	"os"

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

// Helper to prepare the header for output
func stringSliceToAnySlice(header []string) []any {
	result := make([]any, len(header))
	for i, v := range header {
		result[i] = v
	}
	return result
}

// Helper to get the shell username
func getShellUsername() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "cli-user"
	} else {
		user = "env: " + user
	}
	return user
}
