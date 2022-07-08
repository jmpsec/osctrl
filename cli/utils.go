package main

import (
	"fmt"
	"unicode/utf8"

	"github.com/jmpsec/osctrl/users"
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
