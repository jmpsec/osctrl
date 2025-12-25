package auditlog

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	// Log types
	LogTypeLogin       = 1
	LogTypeLogout      = 2
	LogTypeNode        = 3
	LogTypeQuery       = 4
	LogTypeCarve       = 5
	LogTypeTag         = 6
	LogTypeEnvironment = 7
	LogTypeSetting     = 8
	LogTypeVisit       = 9
	LogTypeUser        = 10
	// Severities
	SeverityInfo    = 1
	SeverityWarning = 2
	SeverityError   = 3
	// No environment action
	NoEnvironment = 0
)

// AuditLog to store all audit logs
type AuditLog struct {
	gorm.Model
	Service       string
	Username      string
	Line          string
	LogType       uint
	Severity      uint
	SourceIP      string
	EnvironmentID uint
}

// AuditLogManager for audit logs
type AuditLogManager struct {
	DB      *gorm.DB
	Service string
	Enabled bool
}

// CreateAuditLogManager to initialize the audit log struct and tables
func CreateAuditLogManager(backend *gorm.DB, service string, enabled bool) (*AuditLogManager, error) {
	t := &AuditLogManager{
		DB:      backend,
		Service: service,
		Enabled: enabled,
	}
	// table audit_log
	if err := backend.AutoMigrate(&AuditLog{}); err != nil {
		return t, fmt.Errorf("failed to AutoMigrate table (audit_log): %w", err)
	}
	return t, nil
}

// New audit log entry
func (m *AuditLogManager) New(username, line, ip string, logType, severity, envID uint) (AuditLog, error) {
	var alog AuditLog
	if line == "" {
		return alog, fmt.Errorf("empty log line")
	}
	return AuditLog{
		Service:       m.Service,
		Username:      username,
		Line:          line,
		LogType:       logType,
		Severity:      severity,
		SourceIP:      ip,
		EnvironmentID: envID,
	}, nil
}

// Create new audit log entry
func (m *AuditLogManager) Create(logLine *AuditLog) error {
	if !m.Enabled {
		return nil
	}
	if err := m.DB.Create(&logLine).Error; err != nil {
		return fmt.Errorf("create AuditLog %w", err)
	}
	return nil
}

// CreateNew - create new audit log entry
func (m *AuditLogManager) CreateNew(username, line, ip string, logType, severity, envID uint) error {
	if !m.Enabled {
		return nil
	}
	logLine, err := m.New(username, line, ip, logType, severity, envID)
	if err != nil {
		return fmt.Errorf("new AuditLog %w", err)
	}
	if err := m.Create(&logLine); err != nil {
		return fmt.Errorf("create AuditLog %w", err)
	}
	return nil
}

// NewLogin - create new login audit log entry
func (m *AuditLogManager) NewLogin(username, ip string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s logged in", username)
	if err := m.CreateNew(username, line, ip, LogTypeLogin, SeverityInfo, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating login audit log")
	}
}

// NewLogout - create new logout audit log entry
func (m *AuditLogManager) NewLogout(username, ip string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s logged out", username)
	if err := m.CreateNew(username, line, ip, LogTypeLogout, SeverityInfo, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating logout audit log")
	}
}

// NewQuery - create new query audit log entry
func (m *AuditLogManager) NewQuery(username, query, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s created new query: %s", username, query)
	if err := m.CreateNew(username, line, ip, LogTypeQuery, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating new query audit log")
	}
}

// NewCarve - create new carve audit log entry
func (m *AuditLogManager) NewCarve(username, path, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s created new carve for: %s", username, path)
	if err := m.CreateNew(username, line, ip, LogTypeCarve, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating new carve audit log")
	}
}

// QueryAction - create new query action audit log entry
func (m *AuditLogManager) QueryAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed query action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeNode, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating query action audit log")
	}
}

// CarveAction - create new carve action audit log entry
func (m *AuditLogManager) CarveAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed carve action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeCarve, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating carve action audit log")
	}
}

// Visit - create new visit tag audit log entry
func (m *AuditLogManager) Visit(username, path, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s visited path: %s", username, path)
	if err := m.CreateNew(username, line, ip, LogTypeVisit, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating visit audit log")
	}
}

// NewToken - create new token audit log entry
func (m *AuditLogManager) NewToken(username, ip string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s refreshed API token", username)
	if err := m.CreateNew(username, line, ip, LogTypeUser, SeverityInfo, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating token audit log")
	}
}

// ConfAction - create new configuration action audit log entry
func (m *AuditLogManager) ConfAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed configuration action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeEnvironment, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating configuration action audit log")
	}
}

// NodeAction - create new node action audit log entry
func (m *AuditLogManager) NodeAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed node action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeNode, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating node action audit log")
	}
}

// EnvAction - create new environment action audit log entry
func (m *AuditLogManager) EnvAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed environment action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeEnvironment, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating environment action audit log")
	}
}

// SettingsAction - create new settings action audit log entry
func (m *AuditLogManager) SettingsAction(username, action, ip string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed settings action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeSetting, SeverityInfo, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating settings action audit log")
	}
}

// TagAction - create new tag action audit log entry
func (m *AuditLogManager) TagAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed tag action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeTag, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating tag action audit log")
	}
}

// UserAction - create new user action audit log entry
func (m *AuditLogManager) UserAction(username, action, ip string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed user action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeUser, SeverityInfo, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating user action audit log")
	}
}

// Permissions - create new permissions action audit log entry
func (m *AuditLogManager) Permissions(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s changed permissions: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeUser, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating permissions action audit log")
	}
}

// GetAll - get all audit logs
func (m *AuditLogManager) GetAll() ([]AuditLog, error) {
	var logs []AuditLog
	if err := m.DB.Order("created_at desc").Find(&logs).Error; err != nil {
		return logs, fmt.Errorf("get all AuditLog %w", err)
	}
	return logs, nil
}

// GetByEnv - get audit logs by environment
func (m *AuditLogManager) GetByEnv(envID uint) ([]AuditLog, error) {
	var logs []AuditLog
	if err := m.DB.Where("environment_id = ?", envID).Order("created_at desc").Find(&logs).Error; err != nil {
		return logs, fmt.Errorf("get AuditLog by env %w", err)
	}
	return logs, nil
}

// GetByType - get audit logs by type and environment
func (m *AuditLogManager) GetByTypeEnv(logType, envID uint) ([]AuditLog, error) {
	var logs []AuditLog
	if err := m.DB.Where("log_type = ? AND environment_id = ?", logType, envID).Order("created_at desc").Find(&logs).Error; err != nil {
		return logs, fmt.Errorf("get AuditLog by type and environment %w", err)
	}
	return logs, nil
}

// GetBySeverityEnv - get audit logs by severity and environment
func (m *AuditLogManager) GetBySeverityEnv(severity, envID uint) ([]AuditLog, error) {
	var logs []AuditLog
	if err := m.DB.Where("severity = ? AND environment_id = ?", severity, envID).Order("created_at desc").Find(&logs).Error; err != nil {
		return logs, fmt.Errorf("get AuditLog by severity and environment %w", err)
	}
	return logs, nil
}
