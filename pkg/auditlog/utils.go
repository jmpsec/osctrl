package auditlog

// LogTypeToString to convert log type to string
func LogTypeToString(logType uint) string {
	switch logType {
	case 1:
		return "Login"
	case 2:
		return "Logout"
	case 3:
		return "Node"
	case 4:
		return "Query"
	case 5:
		return "Carve"
	case 6:
		return "Tag"
	case 7:
		return "Environment"
	case 8:
		return "Setting"
	case 9:
		return "Visit"
	case 10:
		return "User"
	default:
		return "Unknown"
	}
}

// SeverityToString to convert severity to string
func SeverityToString(severity uint) string {
	switch severity {
	case 1:
		return "Info"
	case 2:
		return "Warning"
	case 3:
		return "Error"
	default:
		return "Unknown"
	}
}
