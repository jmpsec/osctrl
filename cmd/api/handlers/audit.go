package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// AuditLogsHandler - GET Handler for all audit logs
func (h *HandlersApi) AuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get audit logs
	auditLogs, err := h.AuditLog.GetAll()
	if err != nil {
		log.Err(err).Msg("error getting audit logs")
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned %d audit log entries", len(auditLogs))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, auditLogs)
}
