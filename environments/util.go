package environments

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"time"

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
	id := ksuid.New()
	return id.String()
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
