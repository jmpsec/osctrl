package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
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

// Helper to handle API error responses
func apiErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Debug().Msgf("apiErrorResponse %s: %v", msg, err)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, types.ApiErrorResponse{Error: msg})
}
