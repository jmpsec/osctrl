package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytesReceivedConversionBytes(t *testing.T) {
	assert.NotEmpty(t, BytesReceivedConversion(123))
	assert.Equal(t, "123 bytes", BytesReceivedConversion(123))
}

func TestBytesReceivedConversionKBytes(t *testing.T) {
	assert.NotEmpty(t, BytesReceivedConversion(1024))
	assert.Equal(t, "1.0 KB", BytesReceivedConversion(1024))
}

func TestBytesReceivedConversionMBytes(t *testing.T) {
	assert.NotEmpty(t, BytesReceivedConversion(1048576))
	assert.Equal(t, "1.0 MB", BytesReceivedConversion(1048576))
}
