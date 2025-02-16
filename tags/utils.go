package tags

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const (
	// TagTypeEnvironmentStr is the tag type for environment
	TagTypeEnvironmentStr = "Environment"
	// TagTypeEnvStr is the tag type for shortened environment
	TagTypeEnvStr = "Env"
	// TagTypeUUIDStr is the tag type for UUID
	TagTypeUUIDStr = "UUID"
	// TagTypePlatformStr is the tag type for platform
	TagTypePlatformStr = "Platform"
	// TagTypeLocalnameStr is the tag type for localname
	TagTypeLocalnameStr = "Localname"
	// TagTypeCustomStr is the tag type for custom
	TagTypeCustomStr = "Custom"
	// TagTypeUnknownStr is the tag type for unknown
	TagTypeUnknownStr = "Unknown"
)

// Helper to generate a random color in hex for HTML
func RandomColor() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	red := r.Intn(255)
	green := r.Intn(255)
	blue := r.Intn(255)

	return "#" + GetHex(red) + GetHex(green) + GetHex(blue)
}

// Helper to get the hex from an int
func GetHex(num int) string {
	hex := fmt.Sprintf("%x", num)
	if len(hex) == 1 {
		hex = "0" + hex
	}
	return hex
}

// Helper to convert the tag type to a string
func TagTypeDecorator(tagType uint) string {
	switch tagType {
	case TagTypeEnv:
		return TagTypeEnvironmentStr
	case TagTypeUUID:
		return TagTypeUUIDStr
	case TagTypePlatform:
		return TagTypePlatformStr
	case TagTypeLocalname:
		return TagTypeLocalnameStr
	case TagTypeCustom:
		return TagTypeCustomStr
	default:
		return TagTypeUnknownStr
	}
}

// Helper to convert the tag type string to a uint
func TagTypeParser(tagType string) uint {
	switch strings.ToUpper(tagType) {
	case strings.ToUpper(TagTypeEnvStr):
		return TagTypeEnv
	case strings.ToUpper(TagTypeUUIDStr):
		return TagTypeUUID
	case strings.ToUpper(TagTypePlatformStr):
		return TagTypePlatform
	case strings.ToUpper(TagTypeLocalnameStr):
		return TagTypeLocalname
	case strings.ToUpper(TagTypeCustomStr):
		return TagTypeCustom
	default:
		return TagTypeUnknown
	}
}
