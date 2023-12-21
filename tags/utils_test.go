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
