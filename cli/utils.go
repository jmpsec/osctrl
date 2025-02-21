package main

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// Helper to truncate a string
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n] + "..."
}

// Helper to convert boolean to string
func stringifyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// Helper to format
func stringifyEnvAccess(access users.EnvAccess) string {
	res := ""
	if access.User {
		res += "U"
	}
	if access.Admin {
		res += "|A"
	}
	if access.Query {
		res += "|Q"
	}
	if access.Carve {
		res += "|C"
	}
	return res
}

// Helper to format user permissions to display
func stringifyUserAccess(perms users.UserAccess) string {
	res := ""
	for e, p := range perms {
		env, _ := envs.Get(e)
		res += fmt.Sprintf("%s [%s]\n", env.Name, stringifyEnvAccess(p))
	}
	return res
}

// Helper to get what is the last seen time for a node
func nodeLastSeen(n nodes.OsqueryNode) string {
	now := time.Now()
	var diff float64
	var res string
	// Status if not empty/zero
	if !n.LastStatus.IsZero() {
		diff = n.LastStatus.Sub(now).Seconds()
		res = utils.PastFutureTimes(n.LastStatus) + " (status)"
	}
	// Result if not empty/zero
	if n.LastResult.Year() == now.Year() {
		diffResult := n.LastResult.Sub(now).Seconds()
		if diffResult < diff {
			res = utils.PastFutureTimes(n.LastResult) + " (result)"
			diff = diffResult
		}
	}
	// Config if not empty/zero
	if n.LastConfig.Year() == now.Year() {
		diffConfig := n.LastConfig.Sub(now).Seconds()
		if diffConfig < diff {
			res = utils.PastFutureTimes(n.LastConfig) + " (config)"
			diff = diffConfig
		}
	}
	// Query read if not empty/zero
	if n.LastQueryRead.Year() == now.Year() {
		diffRead := n.LastQueryRead.Sub(now).Seconds()
		if diffRead < diff {
			res = utils.PastFutureTimes(n.LastQueryRead) + " (query)"
			diff = diffRead
		}
	}
	// Query write if not empty/zero
	if n.LastQueryWrite.Year() == now.Year() {
		diffWrite := n.LastQueryWrite.Sub(now).Seconds()
		if diffWrite < diff {
			res = utils.PastFutureTimes(n.LastQueryWrite) + " (write)"
			diff = diffWrite
		}
	}
	return res
}
