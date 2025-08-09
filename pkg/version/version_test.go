package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOsqueryVersion(t *testing.T) {
	assert.Equal(t, "5.18.1", OsqueryVersion)
}

func TestOsctrlVersion(t *testing.T) {
	assert.Equal(t, "0.4.5", OsctrlVersion)
}
