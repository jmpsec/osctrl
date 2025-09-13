package environments

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ReadExternalFile to read an external file and return contents
func ReadExternalFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

// IsItExpired to determine if a time has expired, which makes it in the past
func IsItExpired(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	now := time.Now()
	return (int(t.Sub(now).Seconds()) <= 0)
}

// IsPlatformQuery to know if a plaform is going to trigger a query
func IsPlatformQuery(pQuery, pCheck string) bool {
	// Empty plaform means all platforms
	if pQuery == "" || pQuery == "all" || pQuery == "any" {
		return true
	}
	// Check if platform is posix (darwin, freebsd, linux)
	if pQuery == "posix" && (pCheck == "darwin" || pCheck == "freebsd" || pCheck == "linux" || IsPlatformLinux(strings.ToLower(pCheck))) {
		return true
	}
	// Last check is platform itself
	return (pQuery == pCheck)
}

// IsPlatformLinux to know if a linux is going to trigger a query
func IsPlatformLinux(pCheck string) bool {
	return (pCheck == "ubuntu" || pCheck == "centos" || pCheck == "rhel" || pCheck == "fedora" || pCheck == "debian" || pCheck == "opensuse" || pCheck == "arch" || pCheck == "amzn")
}

// PackageDownloadURL to get the download URL for a package
func PackageDownloadURL(env TLSEnvironment, pkg string) string {
	if pkg == "" {
		return ""
	}
	if strings.HasPrefix(pkg, "https://") {
		return pkg
	}
	return fmt.Sprintf("https://%s/%s/%s/package/%s", env.Hostname, env.UUID, env.Secret, pkg)
}

// EnvironmentFinderID to find the environment and return its name based on the environment ID
func EnvironmentFinderID(envID uint, envs []TLSEnvironment, uuid bool) string {
	for _, env := range envs {
		if env.ID == envID {
			if uuid {
				return env.UUID
			}
			return env.Name
		}
	}
	return "Unknown"
}

// EnvironmentFinderUUID to find the environment and return its name based on the environment UUID
func EnvironmentFinderUUID(envIdentifier string, envs []TLSEnvironment) string {
	for _, env := range envs {
		if env.UUID == envIdentifier || env.Name == envIdentifier {
			return env.Name
		}
	}
	return "Unknown"
}
