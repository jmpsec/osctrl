package environments

import "regexp"

const (
	iconRegex     string = `^[a-z0-9_-]+$`
	nameRegex     string = `^[a-zA-Z0-9_-]+$`
	hostnameRegex string = `^[a-zA-Z0-9.\-]+$`
	uuidRegex     string = `^[a-z0-9-]+$`
	envOsquery    string = "osquery"
)

// Valid values for environment type in configuration
var validType = map[string]bool{
	envOsquery: true,
}

// IconFilter - Helper to filter the icon name to prevent unsanitized input
func IconFilter(s string) bool {
	// regex to only allow lowercase letters, numbers, dashes and underscores
	re := regexp.MustCompile(iconRegex)
	return re.MatchString(s)
}

// EnvTypeFilter - Helper to filter the environment type to prevent unsanitized input
func EnvTypeFilter(s string) bool {
	return validType[s]
}

// HostnameFilter - Helper to filter the hostname to prevent unsanitized input
func HostnameFilter(s string) bool {
	// regex to only allow uppercase and lowercase letters, numbers, dashes and dots
	re := regexp.MustCompile(hostnameRegex)
	return re.MatchString(s)
}

// EnvNameFilter - Helper to filter the environment name to prevent unsanitized input
func EnvNameFilter(s string) bool {
	// regex to only allow letters, numbers, dashes and underscores
	re := regexp.MustCompile(nameRegex)
	return re.MatchString(s)
}

// EnvUUIDFilter - Helper to filter the environment uuid to prevent unsanitized input
func EnvUUIDFilter(s string) bool {
	// regex to only allow lowercase letters, numbers and dashes
	re := regexp.MustCompile(uuidRegex)
	return re.MatchString(s)
}

// VerifyEnvFilters to verify all filters for an environment
func VerifyEnvFilters(name, icon, sType, hostname string) bool {
	if !EnvNameFilter(name) {
		return false
	}
	if !IconFilter(icon) {
		return false
	}
	if !EnvTypeFilter(sType) {
		return false
	}
	if !HostnameFilter(hostname) {
		return false
	}
	return true
}
