package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Oversized anonymous login input is rejected before credential lookup and
// never reaches the audit table.
func TestLoginRejectsOversizedInputBeforeAudit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceAPI, true)
	require.NoError(t, err)
	h := &HandlersApi{Users: users.CreateUserManager(db), AuditLog: audit, DebugHTTPConfig: &config.YAMLConfigurationDebug{}}

	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"body over cap":     {`{"username":"` + strings.Repeat("a", authMaxBody) + `"}`, http.StatusBadRequest},
		"username too long": {`{"username":"` + strings.Repeat("a", maxLoginUsername+1) + `","password":"x"}`, http.StatusForbidden},
		"password too long": {`{"username":"a","password":"` + strings.Repeat("x", maxLoginPassword+1) + `"}`, http.StatusForbidden},
	} {
		w := httptest.NewRecorder()
		h.LoginHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(tc.body)))
		require.Equal(t, tc.code, w.Code, name)
	}
	var n int64
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Count(&n).Error)
	require.Zero(t, n)

	audit.FailedLogin(strings.Repeat("u", 10_000), "10.0.0.1", "invalid credentials")
	var row auditlog.AuditLog
	require.NoError(t, db.First(&row).Error)
	require.LessOrEqual(t, len(row.Username), 260)
}
