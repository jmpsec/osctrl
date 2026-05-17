package saml

import (
	"sync"
	"time"
)

// replayCache is a small TTL-bound set of recently-seen assertion IDs.
// SAML's protocol-level replay defense (NotBefore/NotOnOrAfter windows)
// leaves a window — usually a few minutes — during which an attacker
// who captured a valid SAMLResponse can replay it before the IdP's
// stated expiry. We close that window by remembering every assertion
// ID we've consumed and refusing duplicates.
//
// Threat S3 in the spec. The window is sized by Config.ReplayWindow
// (default 5 min), matching the SAML clock-skew tolerance.
//
// Implementation notes:
//
//   - Lock granularity is the whole map. Acceptable for SSO traffic
//     (logins/sec rarely exceed double digits even at scale).
//   - We sweep expired entries opportunistically on each remember()
//     call. No background goroutine, so the cache footprint is bounded
//     by traffic rate × window.
//   - The cache is per-process. Multi-replica deployments accept a
//     small replay window per replica — operators who want strict
//     cluster-wide enforcement can layer a shared cache (Redis), but
//     v1 keeps the protocol layer dependency-free.
type replayCache struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{
		window: window,
		seen:   make(map[string]time.Time),
	}
}

// remember records the assertion ID with the current timestamp. Returns
// true if this was a new ID (caller proceeds), false if the ID is
// already in the cache and still within the window (caller rejects).
//
// Empty IDs are accepted without recording — the SAML spec requires
// assertions to have an ID, but if a real-world IdP emits a blank one
// we still proceed (with the protocol-level replay window the only
// defense). Validated assertions with empty IDs are vanishingly rare
// and crewjam already enforces a lot of structural constraints.
func (c *replayCache) remember(id string) bool {
	if id == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-c.window)

	// Opportunistic sweep so the map doesn't grow unbounded under
	// sustained load. Iterating the whole map on every call is fine
	// for SSO scale; if this ever becomes hot we can switch to a
	// ring buffer.
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}

	if _, present := c.seen[id]; present {
		return false
	}
	c.seen[id] = now
	return true
}
