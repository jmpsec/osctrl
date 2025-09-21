package tags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomColor(t *testing.T) {
	color1 := RandomColor()
	color2 := RandomColor()
	assert.NotEqual(t, false, color1 != color2)
}

func TestGetHex(t *testing.T) {
	assert.Equal(t, "00", GetHex(0))
	assert.Equal(t, "0a", GetHex(10))
	assert.Equal(t, "ff", GetHex(255))
}

func TestTagTypeDecorator(t *testing.T) {
	assert.Equal(t, "env", TagTypeDecorator(0))
	assert.Equal(t, "uuid", TagTypeDecorator(1))
	assert.Equal(t, "platform", TagTypeDecorator(2))
	assert.Equal(t, "localname", TagTypeDecorator(3))
	assert.Equal(t, "custom", TagTypeDecorator(4))
	assert.Equal(t, "unknown", TagTypeDecorator(5))
}

func TestTagTypeParser(t *testing.T) {
	assert.Equal(t, uint(0), TagTypeParser("env"))
	assert.Equal(t, uint(1), TagTypeParser("uuid"))
	assert.Equal(t, uint(2), TagTypeParser("platform"))
	assert.Equal(t, uint(3), TagTypeParser("localname"))
	assert.Equal(t, uint(4), TagTypeParser("custom"))
	assert.Equal(t, uint(5), TagTypeParser("unknown"))
}

func TestTagCustom(t *testing.T) {
	assert.Equal(t, "env", SetCustomTag(0, "CUSTOM-VALUE"))
	assert.Equal(t, "uuid", SetCustomTag(1, "CUSTOM-VALUE"))
	assert.Equal(t, "platform", SetCustomTag(2, "CUSTOM-VALUE"))
	assert.Equal(t, "localname", SetCustomTag(3, "CUSTOM-VALUE"))
	assert.Equal(t, "CUSTOM-VALUE", SetCustomTag(4, "CUSTOM-VALUE"))
	assert.Equal(t, "unknown", SetCustomTag(5, "CUSTOM-VALUE"))
}

func TestGetStrTagName(t *testing.T) {
	assert.Equal(t, "VALUE", GetStrTagName("custom:VALUE"))
	assert.Equal(t, "VALUE:EXTRA", GetStrTagName("custom:VALUE:EXTRA"))
	assert.Equal(t, "VALUE", GetStrTagName("VALUE"))
}

func TestValidateCustom(t *testing.T) {
	assert.Equal(t, "custom", ValidateCustom("custom"))
	assert.Equal(t, "unknown", ValidateCustom("anything"))
	assert.Equal(t, "unknown", ValidateCustom(""))
}
