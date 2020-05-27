package handlers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// JSONTagsHandler for platform/environment stats in JSON
func (h *HandlersAdmin) JSONTagsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Get tags
	tags, err := h.Tags.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error getting tags %v", err)
		return
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
	h.Inc(metricJSONOK)
}
