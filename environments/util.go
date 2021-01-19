package environments

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/ksuid"
)

const (
	errorRandomString string = "SomethingRandomWentWrong"
)

// Helper to generate a random string of n characters
func generateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return errorRandomString
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Helper to generate a KSUID
// See https://github.com/segmentio/ksuid for more info about KSUIDs
func generateKSUID() string {
	return ksuid.New().String()
}

// Helper to generate a UUID
// See https://github.com/google/uuid for more info about UUIDs
func generateUUID() string {
	return uuid.New().String()
}

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
