package utils

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"

	"github.com/google/uuid"
	"github.com/segmentio/ksuid"
)

const (
	errorRandomString string = "SomethingRandomWentWrong"
)

// GenRandomString - Helper to generate a random string of n characters
func GenRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return errorRandomString
	}
	return base64.URLEncoding.EncodeToString(b)[:n]
}

// GenKSUID - Helper to generate a KSUID
// See https://github.com/segmentio/ksuid for more info about KSUIDs
func GenKSUID() string {
	return ksuid.New().String()
}

// GenUUID - Helper to generate a UUID
// See https://github.com/google/uuid for more info about UUIDs
func GenUUID() string {
	return uuid.New().String()
}

// StringToInteger - Helper to convert a string into integer
func StringToInteger(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// StringToBoolean - Helper to convert a string into boolean
func StringToBoolean(s string) bool {
	if s == "yes" || s == "true" || s == "1" {
		return true
	}
	return false
}
