package apiclient

import (
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
)

// GetAuditLogs to retrieve all audit logs from osctrl. Non-admin users only
// get their own entries, as enforced by the API.
func (api *OsctrlAPI) GetAuditLogs() ([]auditlog.AuditLog, error) {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIAuditLogs))
	views, err := getAllPages[types.AuditLogView](api, reqURL)
	if err != nil {
		return nil, err
	}
	als := make([]auditlog.AuditLog, 0, len(views))
	for _, v := range views {
		als = append(als, auditlog.AuditLog{
			Model:         gorm.Model{ID: v.ID, CreatedAt: v.CreatedAt},
			Service:       v.Service,
			Username:      v.Username,
			Line:          v.Line,
			LogType:       v.LogType,
			Severity:      v.Severity,
			SourceIP:      v.SourceIP,
			EnvironmentID: v.EnvironmentID,
		})
	}
	return als, nil
}
