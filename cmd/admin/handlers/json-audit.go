package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// AuditLogJSON to be used to populate JSON data for audit logs
type AuditLogJSON struct {
	Service  string        `json:"service"`
	Username string        `json:"username"`
	Line     string        `json:"line"`
	SourceIP string        `json:"sourceip"`
	LogType  string        `json:"logtype"`
	Severity string        `json:"severity"`
	Env      string        `json:"environment"`
	When     CreationTimes `json:"when"`
}

// ReturnedAudit to return a JSON with audit logs
type ReturnedAudit struct {
	Data []AuditLogJSON `json:"data"`
}

// JSONAuditLogHandler for audit logs in JSON
func (h *HandlersAdmin) JSONAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insufficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Get all environments
	envs, err := h.Envs.All()
	if err != nil {
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get audit logs
	auditLogs, err := h.AuditLog.GetAll()
	if err != nil {
		log.Err(err).Msg("error getting audit logs")
		return
	}
	// Prepare data to be returned
	var auditLogsJSON []AuditLogJSON
	for _, logEntry := range auditLogs {
		auditLogsJSON = append(auditLogsJSON, AuditLogJSON{
			Service:  logEntry.Service,
			Username: logEntry.Username,
			Line:     logEntry.Line,
			SourceIP: logEntry.SourceIP,
			LogType:  h.AuditLog.LogTypeToString(logEntry.LogType),
			Severity: h.AuditLog.SeverityToString(logEntry.Severity),
			Env:      environments.EnvironmentFinderID(logEntry.EnvironmentID, envs, false),
			When: CreationTimes{
				Display: utils.PastFutureTimes(logEntry.CreatedAt),
				// Use Unix timestamp in seconds
				Timestamp: utils.TimeTimestamp(logEntry.CreatedAt),
			},
		})
	}
	returned := ReturnedAudit{
		Data: auditLogsJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}
