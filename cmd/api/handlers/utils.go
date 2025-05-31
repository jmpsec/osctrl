package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// ContextValue to hold session data in the context
type ContextValue map[string]string

// ContextKey to help with the context key, to pass session data
type ContextKey string

// APIQueryData to hold query result data
type APIQueryData map[string]string

const (
	// Key to identify request context
	contextAPI string = "osctrl-api-context"
	ctxUser    string = "user"
)

// Function to retrieve the query log by name
func postgresQueryLogs(db *gorm.DB, name string) (APIQueryData, error) {
	var logs []logging.OsqueryQueryData
	data := make(APIQueryData)
	if err := db.Where("name = ?", name).Find(&logs).Error; err != nil {
		return data, err
	}
	for _, l := range logs {
		data[l.UUID] = l.Data
	}
	return data, nil
}

// Helper to handle API error responses
func apiErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Debug().Msgf("apiErrorResponse %s: %v", msg, err)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, types.ApiErrorResponse{Error: msg})
}

// Helper to verify if a platform is valid
func checkValidPlatform(platforms []string, platform string) bool {
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// Helper to convert a node into a ApiLookupResponse
func _nodeToApiLookupResponse(node nodes.OsqueryNode) types.ApiLookupResponse {
	return types.ApiLookupResponse{
		UUID:            node.UUID,
		Platform:        node.Platform,
		PlatformVersion: node.PlatformVersion,
		OsqueryVersion:  node.OsqueryVersion,
		Hostname:        node.Hostname,
		Localname:       node.Localname,
		IPAddress:       node.IPAddress,
		Username:        node.Username,
		Environment:     node.Environment,
		HardwareSerial:  node.HardwareSerial,
		LastSeen:        node.LastSeen.String(),
	}
}
