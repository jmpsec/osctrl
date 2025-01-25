package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOsqueryVersion(t *testing.T) {
	assert.Equal(t, "5.15.0", OsqueryVersion)
}

func TestOsctrlVersion(t *testing.T) {
	assert.Equal(t, "0.4.2", OsctrlVersion)
}
