package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// SessionFreshness is the maximum age of an interactive session heartbeat.
const SessionFreshness = 30 * time.Second

const (
	sessionHintTTL    = 5 * time.Second
	sessionAbsenceTTL = 2 * time.Minute
)

// SessionHints caches polling hints only; session authorization stays in SQL.
// Absence lasts two minutes to cover normal 60-second polling; presence lasts
// at most five seconds and never beyond the session heartbeat's freshness.
type SessionHints struct {
	client *redis.Client
}

func NewSessionHints(client *redis.Client) *SessionHints {
	return &SessionHints{client: client}
}

type sessionHint struct {
	Active bool
	Until  time.Time
}

// Active loads the latest active session's updated_at (zero means absent).
// A token acquired before SQL and atomically checked at refill prevents a
// concurrent invalidation from being overwritten, including on an empty key.
func (c *SessionHints) Active(ctx context.Context, kind string, envID, nodeID uint, nodeUUID string, load func() (time.Time, error)) (bool, error) {
	if c == nil || c.client == nil {
		updated, err := load()
		return !updated.IsZero() && time.Now().Before(updated.Add(SessionFreshness)), err
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	key := sessionHintKey(kind, envID, nodeID, nodeUUID)
	value, err := c.client.Get(ctx, key).Bytes()
	var hint sessionHint
	if err == nil && json.Unmarshal(value, &hint) == nil && time.Now().Before(hint.Until) {
		return hint.Active, nil
	}
	if err != nil && !errors.Is(err, redis.Nil) {
		log.Debug().Err(err).Msg("session hint read failed; falling back to SQL")
		updated, sqlErr := load()
		return !updated.IsZero() && time.Now().Before(updated.Add(SessionFreshness)), sqlErr
	}
	token := uuid.NewString()
	owned, _ := c.client.SetNX(ctx, key, token, sessionHintTTL).Result()
	checkedAt := time.Now()
	updated, err := load()
	if err != nil {
		return false, err
	}
	active := !updated.IsZero() && time.Now().Before(updated.Add(SessionFreshness))
	ttl := sessionHintTTL
	if !active {
		ttl = sessionAbsenceTTL
	}
	deadline := checkedAt.Add(ttl)
	if active && updated.Add(SessionFreshness).Before(deadline) {
		deadline = updated.Add(SessionFreshness)
	}
	if owned && time.Until(deadline) >= time.Millisecond {
		value, _ := json.Marshal(sessionHint{Active: active, Until: deadline})
		if err := c.client.Eval(ctx, `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
end
return 0`, []string{key}, token, value, time.Until(deadline).Milliseconds()).Err(); err != nil {
			log.Debug().Err(err).Msg("session hint refill failed")
		}
	}
	return active, nil
}

// Invalidate must run after the SQL mutation commits. A failed invalidation
// can hide a new/refreshed session for two minutes; stale presence lasts at
// most five seconds, never beyond session freshness.
func (c *SessionHints) Invalidate(ctx context.Context, kind string, envID, nodeID uint, nodeUUID string) {
	if c == nil || c.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := c.client.Del(ctx, sessionHintKey(kind, envID, nodeID, nodeUUID)).Err(); err != nil {
		log.Debug().Err(err).Msg("session hint invalidation failed")
	}
}

func sessionHintKey(kind string, envID, nodeID uint, nodeUUID string) string {
	return fmt.Sprintf("osctrl:tls:session:%s:%d:%d:%s", kind, envID, nodeID, nodeUUID)
}
