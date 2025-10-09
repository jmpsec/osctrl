package auditlog

const (
	// Log type strings
	LogTypeLoginStr   = "Login"
	LogTypeLogoutStr  = "Logout"
	LogTypeNodeStr    = "Node"
	LogTypeQueryStr   = "Query"
	LogTypeCarveStr   = "Carve"
	LogTypeTagStr     = "Tag"
	LogTypeEnvStr     = "Environment"
	LogTypeSettingStr = "Setting"
	LogTypeVisitStr   = "Visit"
	LogTypeUserStr    = "User"
	LogTypeUnknown    = "Unknown"
	// Severity strings
	SeverityInfoStr    = "Info"
	SeverityWarningStr = "Warning"
	SeverityErrorStr   = "Error"
	SeverityUnknownStr = "Unknown"
)

// LogTypeToString to convert log type to string
func LogTypeToString(logType uint) string {
	switch logType {
	case 1:
		return LogTypeLoginStr
	case 2:
		return LogTypeLogoutStr
	case 3:
		return LogTypeNodeStr
	case 4:
		return LogTypeQueryStr
	case 5:
		return LogTypeCarveStr
	case 6:
		return LogTypeTagStr
	case 7:
		return LogTypeEnvStr
	case 8:
		return LogTypeSettingStr
	case 9:
		return LogTypeVisitStr
	case 10:
		return LogTypeUserStr
	default:
		return LogTypeUnknown
	}
}

// SeverityToString to convert severity to string
func SeverityToString(severity uint) string {
	switch severity {
	case 1:
		return SeverityInfoStr
	case 2:
		return SeverityWarningStr
	case 3:
		return SeverityErrorStr
	default:
		return SeverityUnknownStr
	}
}
