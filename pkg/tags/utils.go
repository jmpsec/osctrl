package tags

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const (
	// TagTypeEnvStr is the tag type for shortened environment
	TagTypeEnvStr = "env"
	// TagTypeUUIDStr is the tag type for UUID
	TagTypeUUIDStr = "uuid"
	// TagTypePlatformStr is the tag type for platform
	TagTypePlatformStr = "platform"
	// TagTypeLocalnameStr is the tag type for localname
	TagTypeLocalnameStr = "localname"
	// TagTypeHostnameStr is the tag type for hostname
	TagTypeHostnameStr = "hostname"
	// TagTypeCustomStr is the tag type for custom
	TagTypeCustomStr = "custom"
	// TagTypeUnknownStr is the tag type for unknown
	TagTypeUnknownStr = "unknown"
	// TagTypeTagStr is the tag type for tag
	TagTypeTagStr = "tag"
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
		return TagTypeEnvStr
	case TagTypeUUID:
		return TagTypeUUIDStr
	case TagTypePlatform:
		return TagTypePlatformStr
	case TagTypeLocalname:
		return TagTypeLocalnameStr
	case TagTypeHostname:
		return TagTypeHostnameStr
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

// Helper to define the custom tag value based on the type
func SetCustomTag(tagType uint, custom string) string {
	var tagCustom string
	switch tagType {
	case TagTypeEnv:
		tagCustom = TagCustomEnv
	case TagTypeUUID:
		tagCustom = TagCustomUUID
	case TagTypePlatform:
		tagCustom = TagCustomPlatform
	case TagTypeLocalname:
		tagCustom = TagCustomLocalname
	case TagTypeCustom:
		tagCustom = custom
	case TagTypeUnknown:
		tagCustom = TagCustomUnknown
	case TagTypeTag:
		tagCustom = TagCustomTag
	default:
		tagCustom = TagCustomTag
	}
	return tagCustom
}
