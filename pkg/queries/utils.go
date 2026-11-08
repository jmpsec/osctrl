package queries

import (
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// MaxQueryLength caps the SQL text of an on-demand or saved query in bytes. A
// query is stored and sent to every targeted node until it answers.
const MaxQueryLength = 64 << 10

// Helper to generate a random query name
func GenQueryName() string {
	return "query_" + utils.RandomForNames()
}

// Helper to generate the time.Time for the expiration of a query or carve based on hours
func QueryExpiration(exp int) time.Time {
	return time.Now().Add(time.Duration(exp) * time.Hour)
}

// Helper to check if query is carve
func IsCarveQuery(query string) bool {
	return strings.Contains(strings.ToLower(query), "carves")
}
