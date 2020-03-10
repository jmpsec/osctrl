package main

import (
	"unicode/utf8"
)

// Constants for seconds
const (
	oneMinute   = 60
	oneHour     = 3600
	oneDay      = 86400
	fifteenDays = 1296000
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
