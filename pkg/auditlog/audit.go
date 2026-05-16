package auditlog

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// LogTypes - allowlist of valid log_type filter values. Used by the
// paginated filter to reject arbitrary integers (defense in depth — the
// underlying column is uint so junk values just match nothing, but we
// surface a 400 to the SPA instead of an empty response).
var LogTypes = map[uint]struct{}{
	LogTypeLogin:       {},
	LogTypeLogout:      {},
	LogTypeNode:        {},
	LogTypeQuery:       {},
	LogTypeCarve:       {},
	LogTypeTag:         {},
	LogTypeEnvironment: {},
	LogTypeSetting:     {},
	LogTypeVisit:       {},
	LogTypeUser:        {},
}

// PageFilter describes the inputs accepted by GetPaged.
//
// All string fields are case-insensitive partial matches except Service
// which is an exact match (services are a tiny fixed set: tls / admin /
// osctrl-api). EnvID == 0 means "no env filter" (NOT "the no-environment
// rows" — use a dedicated convention if that's ever needed). LogType == 0
// means "no type filter". Since / Until are RFC3339 timestamps; either may
// be the zero value to mean unset.
type PageFilter struct {
	Service  string
	Username string
	LogType  uint
	EnvID    uint
	Since    time.Time
	Until    time.Time
	Page     int
	PageSize int
}

// GetPaged returns audit logs filtered + paginated. Ordering is fixed at
// created_at DESC so the SPA always shows newest first.
//
// Returns (rows, totalItems, error). On the filtered count the package
// computes that with the same WHERE clause (one extra COUNT round-trip).
func (m *AuditLogManager) GetPaged(f PageFilter) ([]AuditLog, int64, error) {
	if f.PageSize <= 0 {
		f.PageSize = 50
	}
	if f.PageSize > 500 {
		f.PageSize = 500
	}
	if f.Page < 1 {
		f.Page = 1
	}

	q := m.DB.Model(&AuditLog{})
	if f.Service != "" {
		q = q.Where("service = ?", f.Service)
	}
	if f.Username != "" {
		// case-insensitive partial match via LOWER(username) LIKE ...
		q = q.Where("LOWER(username) LIKE ?", "%"+lowerLike(f.Username)+"%")
	}
	if f.LogType > 0 {
		q = q.Where("log_type = ?", f.LogType)
	}
	if f.EnvID > 0 {
		q = q.Where("environment_id = ?", f.EnvID)
	}
	if !f.Since.IsZero() {
		q = q.Where("created_at >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		q = q.Where("created_at <= ?", f.Until)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count AuditLog %w", err)
	}

	var rows []AuditLog
	offset := (f.Page - 1) * f.PageSize
	if err := q.Order("created_at desc").Limit(f.PageSize).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("paged AuditLog %w", err)
	}
	return rows, total, nil
}

// lowerLike normalizes a user-supplied search fragment for LIKE matching:
// strip surrounding whitespace and lowercase. The handler is responsible
// for callers — we do not lift restrictions or accept regex.
func lowerLike(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out = append(out, c)
	}
	return string(out)
}

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

// FailedLogin records a failed login attempt — invalid credentials, missing
// permission, or any other reason the login flow refused to mint a token.
// `reason` is a short free-text string suitable for SoC alerting and MUST
// NOT contain the offered password. Severity warning so it sticks out next
// to the successful-login firehose.
func (m *AuditLogManager) FailedLogin(username, ip, reason string) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("failed login for user %s: %s", username, reason)
	if err := m.CreateNew(username, line, ip, LogTypeLogin, SeverityWarning, NoEnvironment); err != nil {
		log.Err(err).Msg("error creating failed-login audit log")
	}
}

// FailedEnroll records a failed osquery-node enrollment attempt — invalid
// env secret, denied env, malformed payload. Severity warning, scoped to
// the env in the path (envID == 0 when the env itself was the failure
// reason).
func (m *AuditLogManager) FailedEnroll(ip, envName, reason string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("failed enroll for env %s: %s", envName, reason)
	if err := m.CreateNew("osctrl-tls", line, ip, LogTypeNode, SeverityWarning, envID); err != nil {
		log.Err(err).Msg("error creating failed-enroll audit log")
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

// SavedQueryAction - create new saved-query action audit log entry
// (create / update / delete operations on the saved_queries table).
func (m *AuditLogManager) SavedQueryAction(username, action, ip string, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("user %s performed saved-query action: %s", username, action)
	if err := m.CreateNew(username, line, ip, LogTypeQuery, SeverityInfo, envID); err != nil {
		log.Err(err).Msg("error creating saved-query audit log")
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

// Denied records a 403/forbidden access attempt at SeverityWarning so SoC
// dashboards can surface cross-tenant probes. logType pins the resource
// class (LogTypeEnvironment for env handlers, LogTypeNode for node
// handlers, etc.). envID is the env the resource lives in, or
// NoEnvironment when the deny happened before env resolution. The reason
// field is short free text — never echo back the offered credential.
func (m *AuditLogManager) Denied(username, path, ip, reason string, logType, envID uint) {
	if !m.Enabled {
		return
	}
	line := fmt.Sprintf("denied access for user %s to %s: %s", username, path, reason)
	if err := m.CreateNew(username, line, ip, logType, SeverityWarning, envID); err != nil {
		log.Err(err).Msg("error creating denied-access audit log")
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

// GetEnvSince — returns every audit row for the env since the given cutoff,
// log_type + created_at only (Pluck-style). Used by the activity heatmap so
// the dashboard can render a 24-hour fleet-activity strip without scanning
// the full audit_logs table. Smaller fields than GetByEnv to keep the
// payload tiny — 24 hours of a busy env is still small enough to ship to
// the SPA, but trimming to two columns keeps the SQL fast.
func (m *AuditLogManager) GetEnvSince(envID uint, since time.Time) ([]AuditLog, error) {
	var logs []AuditLog
	if err := m.DB.
		Select("id, log_type, created_at").
		Where("environment_id = ? AND created_at >= ?", envID, since).
		Order("created_at asc").
		Find(&logs).Error; err != nil {
		return logs, fmt.Errorf("get AuditLog since %w", err)
	}
	return logs, nil
}

// EnvActivityBucketRow is one (bucket_start, log_type, count) row returned
// from the bucketed env-activity query.
type EnvActivityBucketRow struct {
	BucketStart int64 `gorm:"column:bucket_start"`
	LogType     uint  `gorm:"column:log_type"`
	Cnt         int64 `gorm:"column:cnt"`
}

// GetEnvActivityBucketed — returns audit-log counts grouped by bucket and
// log_type for one env, pushing the binning into SQL. Replaces the
// in-process histogram over GetEnvSince.
func (m *AuditLogManager) GetEnvActivityBucketed(envID uint, since time.Time, bucketSeconds int) ([]EnvActivityBucketRow, error) {
	var dialect string
	switch m.DB.Dialector.Name() {
	case "postgres":
		dialect = fmt.Sprintf("(floor(extract(epoch from created_at) / %d) * %d)::bigint", bucketSeconds, bucketSeconds)
	case "mysql":
		dialect = fmt.Sprintf("(FLOOR(UNIX_TIMESTAMP(created_at) / %d) * %d)", bucketSeconds, bucketSeconds)
	default:
		dialect = fmt.Sprintf("(CAST(strftime('%%s', created_at) AS INTEGER) / %d * %d)", bucketSeconds, bucketSeconds)
	}
	var rows []EnvActivityBucketRow
	if err := m.DB.Model(&AuditLog{}).
		Select(dialect+" AS bucket_start, log_type, COUNT(*) AS cnt").
		Where("environment_id = ? AND created_at >= ?", envID, since).
		Group("bucket_start, log_type").
		Scan(&rows).Error; err != nil {
		return rows, fmt.Errorf("env-activity bucketed: %w", err)
	}
	return rows, nil
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
