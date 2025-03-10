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
	assert.Equal(t, "Environment", TagTypeDecorator(0))
	assert.Equal(t, "UUID", TagTypeDecorator(1))
	assert.Equal(t, "Platform", TagTypeDecorator(2))
	assert.Equal(t, "Localname", TagTypeDecorator(3))
	assert.Equal(t, "Custom", TagTypeDecorator(4))
	assert.Equal(t, "Unknown", TagTypeDecorator(5))
}

func TestTagTypeParser(t *testing.T) {
	assert.Equal(t, uint(0), TagTypeParser("Env"))
	assert.Equal(t, uint(1), TagTypeParser("UUID"))
	assert.Equal(t, uint(2), TagTypeParser("Platform"))
	assert.Equal(t, uint(3), TagTypeParser("Localname"))
	assert.Equal(t, uint(4), TagTypeParser("Custom"))
	assert.Equal(t, uint(5), TagTypeParser("Unknown"))
	assert.Equal(t, uint(5), TagTypeParser("Invalid"))
}
