package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/logging"
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
	ctxUser           = "user"
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
