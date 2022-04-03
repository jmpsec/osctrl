package environments

import (
	"io/ioutil"
	"strings"
	"time"
)

const (
	errorRandomString string = "SomethingRandomWentWrong"
)

// ReadExternalFile to read an external file and return contents
func ReadExternalFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

// IsItExpired to determine if a time has expired, which makes it in the past
func IsItExpired(t time.Time) bool {
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
	return (pCheck == "ubuntu" || pCheck == "centos" || pCheck == "rhel" || pCheck == "fedora" || pCheck == "debian" || pCheck == "opensuse" || pCheck == "arch")
}
