package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenRandomString(t *testing.T) {
	generatedLen := 10
	generated := GenRandomString(generatedLen)
	assert.NotEmpty(t, generated)
	assert.Equal(t, generatedLen, len(generated))
}

func TestGenKSUID(t *testing.T) {
	assert.NotEmpty(t, GenKSUID())
}

func TestGenUUID(t *testing.T) {
	assert.NotEmpty(t, GenUUID())
}

func TestStringToInteger(t *testing.T) {
	assert.Equal(t, int64(123), StringToInteger("123"))
}

func TestStringToIntegerError(t *testing.T) {
	assert.Equal(t, int64(0), StringToInteger("aaa"))
}

func TestStringToBooleanYes(t *testing.T) {
	assert.Equal(t, true, StringToBoolean("yes"))
}

func TestStringToBooleanTrue(t *testing.T) {
	assert.Equal(t, true, StringToBoolean("true"))
}

func TestStringToBooleanWhatever(t *testing.T) {
	assert.Equal(t, false, StringToBoolean("whatever"))
}
