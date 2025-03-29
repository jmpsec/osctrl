package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// JSONTagsHandler for platform/environment stats in JSON
func (h *HandlersAdmin) JSONTagsHandler(w http.ResponseWriter, r *http.Request) {
	if log.Debug().Enabled() {
		utils.DebugHTTPDump(r, false)
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Get tags
	tags, err := h.Tags.All()
	if err != nil {
		log.Err(err).Msg("error getting tags")
		return
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
}
