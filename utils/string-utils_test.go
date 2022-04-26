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
