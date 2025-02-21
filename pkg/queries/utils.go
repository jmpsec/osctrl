package queries

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// Helper to generate a random query name
func GenQueryName() string {
	return "query_" + utils.RandomForNames()
}

// Helper to generate the time.Time for the expiration of a query or carve based on hours
func QueryExpiration(exp int) time.Time {
	return time.Now().Add(time.Duration(exp) * time.Hour)
}
