package nodes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsActive(t *testing.T) {
	now := time.Now()
	node := OsqueryNode{
		LastStatus:     now.Add(-time.Minute * 50),
		LastResult:     now.Add(-time.Minute * 50),
		LastConfig:     now.Add(-time.Minute * 50),
		LastQueryRead:  now.Add(-time.Minute * 50),
		LastQueryWrite: now.Add(-time.Minute * 50),
	}
	assert.True(t, IsActive(node, -1))
}

func TestIsActiveNegative(t *testing.T) {
	now := time.Now()
	node := OsqueryNode{
		LastStatus:     now.Add(-time.Hour * 6),
		LastResult:     now.Add(-time.Hour * 12),
		LastConfig:     now.Add(-time.Hour * 8),
		LastQueryRead:  now.Add(-time.Hour * 6),
		LastQueryWrite: now.Add(-time.Hour * 7),
	}
	assert.False(t, IsActive(node, -5))
}
