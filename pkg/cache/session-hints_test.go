package cache

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// OSCTRL_TEST_REDIS_ADDR must point to a disposable Redis instance.
func sessionHintTestClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to run Redis session hint integration tests")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.Ping(context.Background()).Err())
	return c
}

func TestSessionHintsCachePresenceAndAbsence(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			nodeUUID := uuid.NewString()
			c := NewSessionHints(sessionHintTestClient(t))
			reads := 0
			load := func() (time.Time, error) {
				reads++
				if present {
					return time.Now(), nil
				}
				return time.Time{}, nil
			}
			for range 3 {
				got, err := c.Active(context.Background(), "console", 1, 7, nodeUUID, load)
				require.NoError(t, err)
				require.Equal(t, present, got)
			}
			require.Equal(t, 1, reads)
		})
	}
}

func TestSessionHintsInvalidationPreventsStaleRefill(t *testing.T) {
	for _, wasPresent := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "close"}[wasPresent], func(t *testing.T) {
			nodeUUID := uuid.NewString()
			client := sessionHintTestClient(t)
			reader, writer := NewSessionHints(client), NewSessionHints(client)
			ctx := context.Background()
			_, err := reader.Active(ctx, "console", 1, 7, nodeUUID, func() (time.Time, error) {
				writer.Invalidate(ctx, "console", 1, 7, nodeUUID)
				if wasPresent {
					return time.Now(), nil
				}
				return time.Time{}, nil
			})
			require.NoError(t, err)
			reads := 0
			got, err := reader.Active(ctx, "console", 1, 7, nodeUUID, func() (time.Time, error) {
				reads++
				if !wasPresent {
					return time.Now(), nil
				}
				return time.Time{}, nil
			})
			require.NoError(t, err)
			require.Equal(t, !wasPresent, got)
			require.Equal(t, 1, reads, "invalidation must reject the earlier SQL result")
		})
	}
}

func TestSessionHintsDoNotOutliveFreshness(t *testing.T) {
	c := NewSessionHints(sessionHintTestClient(t))
	nodeUUID := uuid.NewString()
	updated := time.Now().Add(-30*time.Second + 500*time.Millisecond)
	reads := 0
	load := func() (time.Time, error) { reads++; return updated, nil }
	got, err := c.Active(context.Background(), "console", 1, 7, nodeUUID, load)
	require.NoError(t, err)
	require.True(t, got)
	time.Sleep(550 * time.Millisecond)
	got, err = c.Active(context.Background(), "console", 1, 7, nodeUUID, load)
	require.NoError(t, err)
	require.False(t, got)
	require.Equal(t, 2, reads)
}

func TestSessionHintsFallbackOnRedisAndSQLErrors(t *testing.T) {
	nodeUUID := uuid.NewString()
	client := sessionHintTestClient(t)
	c := NewSessionHints(client)
	sqlErr := errors.New("SQL unavailable")
	_, err := c.Active(context.Background(), "console", 1, 7, nodeUUID, func() (time.Time, error) { return time.Time{}, sqlErr })
	require.ErrorIs(t, err, sqlErr)
	got, err := c.Active(context.Background(), "console", 1, 7, nodeUUID, func() (time.Time, error) { return time.Now(), nil })
	require.NoError(t, err)
	require.True(t, got, "SQL errors must not cache absence")
	require.NoError(t, client.Close())
	got, err = c.Active(context.Background(), "console", 1, 7, nodeUUID, func() (time.Time, error) { return time.Now(), nil })
	require.NoError(t, err)
	require.True(t, got, "Redis errors must fall back to SQL")
}

func TestSessionHintsWithoutRedis(t *testing.T) {
	for _, c := range []*SessionHints{nil, NewSessionHints(nil)} {
		for _, tc := range []struct {
			updated time.Time
			want    bool
		}{{time.Time{}, false}, {time.Now().Add(-time.Minute), false}, {time.Now(), true}} {
			got, err := c.Active(context.Background(), "console", 1, 7, "node", func() (time.Time, error) { return tc.updated, nil })
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		}
	}
}

func TestSessionHintsExpireAbsence(t *testing.T) {
	client := sessionHintTestClient(t)
	c := NewSessionHints(client)
	nodeUUID := uuid.NewString()
	got, err := c.Active(context.Background(), "console", 1, 7, nodeUUID, func() (time.Time, error) { return time.Time{}, nil })
	require.NoError(t, err)
	require.False(t, got)
	key := sessionHintKey("console", 1, 7, nodeUUID)
	ttl, err := client.PTTL(context.Background(), key).Result()
	require.NoError(t, err)
	require.Greater(t, ttl, time.Minute, "negative hints must survive a normal 60-second idle poll")
	require.LessOrEqual(t, ttl, 2*time.Minute)
	// Expedite Redis expiration so recovery after a missed invalidation does
	// not require a two-minute integration test.
	require.NoError(t, client.PExpire(context.Background(), key, time.Millisecond).Err())
	time.Sleep(10 * time.Millisecond)
	got, err = c.Active(context.Background(), "console", 1, 7, nodeUUID, func() (time.Time, error) { return time.Now(), nil })
	require.NoError(t, err)
	require.True(t, got)
}
