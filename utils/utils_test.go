package utils_test

import (
	"testing"

	"github.com/jmpsec/osctrl/utils"
	"github.com/stretchr/testify/assert"
)

func TestBytesReceivedConversionBytes(t *testing.T) {
	assert.NotEmpty(t, utils.BytesReceivedConversion(123))
	assert.Equal(t, "123 bytes", utils.BytesReceivedConversion(123))
}

func TestBytesReceivedConversionKBytes(t *testing.T) {
	assert.NotEmpty(t, utils.BytesReceivedConversion(1024))
	assert.Equal(t, "1.0 KB", utils.BytesReceivedConversion(1024))
}

func TestBytesReceivedConversionMBytes(t *testing.T) {
	assert.NotEmpty(t, utils.BytesReceivedConversion(1048576))
	assert.Equal(t, "1.0 MB", utils.BytesReceivedConversion(1048576))
}

func TestRandomForNames(t *testing.T) {
	assert.NotEmpty(t, utils.RandomForNames())
	assert.Equal(t, 32, len(utils.RandomForNames()))
}

func TestIntersect(t *testing.T) {
	var slice1 = []uint{1, 2, 3, 4, 5}
	var slice2 = []uint{3, 4, 5, 6, 7}
	var expected = []uint{3, 4, 5}
	assert.Equal(t, expected, utils.Intersect(slice1, slice2))
	slice1 = utils.Intersect(slice1, slice2)
	assert.Equal(t, expected, slice1)
}

func TestIntersectEmpty(t *testing.T) {
	var slice1 = []uint{}
	var slice2 = []uint{3, 4, 5, 6, 7}
	var expected = []uint{3, 4, 5, 6, 7}
	assert.Equal(t, expected, utils.Intersect(slice1, slice2))
}
