package nodes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheKey(t *testing.T) {
	node := OsqueryNode{
		EnvironmentID: 123,
		UUID:          "uuid",
	}
	assert.Equal(t, CacheKey(node), "node:123:uuid")
}

func TestCacheLastSeenKey(t *testing.T) {
	node := OsqueryNode{
		EnvironmentID: 123,
		UUID:          "uuid",
	}
	assert.Equal(t, CacheLastSeenKey(node), "last_seen:123:uuid")
}

func TestCacheLastSeenKeyStr(t *testing.T) {
	assert.Equal(t, CacheLastSeenKeyStr(123, "uuid"), "last_seen:123:uuid")
}

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

func TestLastSeenTime(t *testing.T) {
	ts := time.Date(2021, 8, 16, 15, 39, 44, 0, time.UTC)
	fixedStr := "2021-08-16T15:39:44Z"
	lastSeenTime, err := LastSeenTime(fixedStr)
	assert.Nil(t, err)
	assert.Equal(t, ts.Format(time.RFC3339), fixedStr)
	assert.Equal(t, ts, lastSeenTime)
}

func TestCacheLastSeenKeysEnv(t *testing.T) {
	assert.Equal(t, CacheLastSeenKeysEnv(123), "last_seen:123:*")
}
