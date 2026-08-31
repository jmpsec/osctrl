package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	redis "github.com/go-redis/redis/v8"
)

// state.go — Redis-backed cooldown / dedupe gate.
//
// The dispatch worker calls Claim before sending a notification. A
// successful claim means "you are the first hit for this rule+entity
// inside the cooldown window" — the notification is sent and an
// alert_history row is written. A failed claim means another hit is
// already in flight (or was recently dispatched) and this one collapses
// into it.
//
// The key design property: the ingest path never touches Redis. Claims
// happen on the worker goroutines, so Redis latency only affects alert
// delivery speed, never osquery ingest.

// DefaultCooldown is used when a rule specifies CooldownMinutes == 0.
// A small non-zero default keeps a flood of identical matches from
// spamming channels when the operator has not thought about cooldowns.
const DefaultCooldown = 15 * time.Minute

// keyPrefix namespaces all alert state keys in the shared Redis.
const keyPrefix = "osctrl:alert:"

// State is the Redis-backed dedupe gate.
type State struct {
	client *redis.Client
	// now is overridable for tests.
	now func() time.Time
}

// NewState builds a cooldown state on top of an existing Redis client
// (the same client the backend cache uses).
func NewState(client *redis.Client) *State {
	return &State{client: client, now: time.Now}
}

// cooldownWindow resolves a rule's cooldown to a duration.
func cooldownWindow(minutes int) time.Duration {
	if minutes <= 0 {
		return DefaultCooldown
	}
	return time.Duration(minutes) * time.Minute
}

// claimKey builds the Redis dedupe key for a hit: rule + entity are the
// collapse dimensions; the detail hash is included so a *different*
// match detail from the same rule+entity still alerts (e.g. two
// different suspicious paths on the same node).
func claimKey(h Hit) string {
	digest := sha256.Sum256([]byte(h.Detail))
	return fmt.Sprintf("%sclaim:%d:%s:%s", keyPrefix, h.RuleID, h.Entity, hex.EncodeToString(digest[:8]))
}

// Claim attempts to reserve the right to notify for a hit. Returns true
// when the caller should dispatch. On a Redis error the claim fails
// open (true): availability of alerting beats perfect dedupe, and a
// Redis outage is not a reason to silently swallow matches.
func (s *State) Claim(ctx context.Context, h Hit) (bool, error) {
	window := cooldownWindow(h.CooldownMinutes)
	ok, err := s.client.SetNX(ctx, claimKey(h), s.now().Unix(), window).Result()
	if err != nil {
		// Fail open with the error surfaced to the caller for logging.
		return true, err
	}
	return ok, nil
}

// Release drops the claim early (used when dispatch fails so the next
// hit can retry without waiting out the window). Best-effort.
func (s *State) Release(ctx context.Context, h Hit) {
	_ = s.client.Del(ctx, claimKey(h)).Err()
}
