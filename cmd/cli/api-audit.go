package main

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/auditlog"
)

// GetAuditLogs to retrieve all audit logs from osctrl
func (api *OsctrlAPI) GetAuditLogs() ([]auditlog.AuditLog, error) {
	var als []auditlog.AuditLog
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIAuditLogs))
	rawAls, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return als, fmt.Errorf("error api request - %w - %s", err, string(rawAls))
	}
	if err := json.Unmarshal(rawAls, &als); err != nil {
		return als, fmt.Errorf("can not parse body - %w", err)
	}
	return als, nil
}
