package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOsqueryVersion(t *testing.T) {
	assert.Equal(t, "5.10.2", OsqueryVersion)
}

func TestOsctrlVersion(t *testing.T) {
	assert.Equal(t, "0.3.4", OsctrlVersion)
}
