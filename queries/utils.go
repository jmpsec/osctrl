package queries

import "github.com/jmpsec/osctrl/utils"

// Helper to generate a random query name
func GenQueryName() string {
	return "query_" + utils.RandomForNames()
}
