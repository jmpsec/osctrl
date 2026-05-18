// Package ratelimit provides a small token-bucket rate-limit middleware
// used to protect anonymous attack surfaces (login, enroll) from
// brute-force / password-spray.
//
// The Limiter is keyed by a caller-supplied function (IP, IP+username,
// etc.) so the same primitive can fan out to per-endpoint policies.
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/jmpsec/osctrl/pkg/utils"
	"golang.org/x/time/rate"
)

// DefaultMaxBuckets is the cap on the per-key map size. Once exceeded,
// new keys all share a single overflow bucket, so an attacker churning
// arbitrary keys (X-Forwarded-For spoofing or a similar primitive in a
// future surface) cannot grow the limiter's memory footprint unbounded.
const DefaultMaxBuckets = 100_000

// Limiter is a sharded map of token buckets keyed by an arbitrary string.
// Buckets age out after `evictAfter` of inactivity so the map doesn't grow
// unbounded. Eviction is amortized — the full O(N) scan runs at most once
// per `evictAfter/2` so a single hot-path Allow doesn't pay the cost.
// When the map exceeds maxBuckets, new keys collapse onto a shared
// overflow bucket; the spray still gets rate-limited (just not per-key)
// and memory stays bounded.
type Limiter struct {
	mu            sync.Mutex
	buckets       map[string]*entry
	overflow      *rate.Limiter
	maxBuckets    int
	rate          rate.Limit
	burst         int
	evictAfter    time.Duration
	lastEviction  time.Time
	evictInterval time.Duration
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New returns a Limiter that allows up to `burst` events per key over `per`,
// with steady-state refill at `burst/per`. evictAfter is the inactivity
// window after which a key's bucket is forgotten — pick something larger
// than `per` so genuine retries don't reset their bucket.
//
// The bucket map is capped at DefaultMaxBuckets entries. Operators that
// need a different cap can construct via NewWithCap.
func New(burst int, per, evictAfter time.Duration) *Limiter {
	return NewWithCap(burst, per, evictAfter, DefaultMaxBuckets)
}

// NewWithCap is New with an explicit ceiling on the per-key map size.
func NewWithCap(burst int, per, evictAfter time.Duration, maxBuckets int) *Limiter {
	interval := evictAfter / 2
	if interval <= 0 {
		interval = time.Second
	}
	if maxBuckets <= 0 {
		maxBuckets = DefaultMaxBuckets
	}
	r := rate.Every(per / time.Duration(burst))
	return &Limiter{
		buckets:       make(map[string]*entry),
		overflow:      rate.NewLimiter(r, burst),
		maxBuckets:    maxBuckets,
		rate:          r,
		burst:         burst,
		evictAfter:    evictAfter,
		evictInterval: interval,
	}
}

// Allow returns true if the supplied key can perform one event under the
// current bucket state. Side-effect: the bucket is created on first use
// and idle buckets are GC'd opportunistically (at most once per
// evictInterval to keep the hot path constant-time). When the map is
// already at maxBuckets and the key has no existing bucket, the call
// falls back to the shared overflow bucket so memory stays bounded.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Amortized eviction: walk the map only when the throttle says it's
	// time. Each Allow is O(1) on the steady-state path. (Cluster-3
	// review item — keeps the lock-held duration bounded under load.)
	if now.Sub(l.lastEviction) >= l.evictInterval {
		for k, e := range l.buckets {
			if now.Sub(e.lastSeen) > l.evictAfter {
				delete(l.buckets, k)
			}
		}
		l.lastEviction = now
	}
	if e, ok := l.buckets[key]; ok {
		e.lastSeen = now
		return e.limiter.Allow()
	}
	// New key. If the map is at the cap, route through the shared
	// overflow bucket — spray attackers can saturate it, but legitimate
	// keys that already have a bucket still get their own quota.
	//
	if len(l.buckets) >= l.maxBuckets {
		return l.overflow.Allow()
	}
	e := &entry{limiter: rate.NewLimiter(l.rate, l.burst), lastSeen: now}
	l.buckets[key] = e
	return e.limiter.Allow()
}

// HTTPMiddleware returns a middleware that rejects requests with 429 when
// `keyFn(r)` exceeds the limit. keyFn is responsible for choosing the
// dimension (e.g., utils.GetIP(r), or `utils.GetIP(r) + ":" + username`).
//
// onReject is invoked synchronously when a request is rejected — use it to
// emit an audit-log entry. May be nil.
func (l *Limiter) HTTPMiddleware(keyFn func(*http.Request) string, onReject func(*http.Request, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if !l.Allow(key) {
				if onReject != nil {
					onReject(r, key)
				}
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// KeyByIP is a convenience keyFn for IP-based rate limiting. Returns
// the direct connection peer's IP via utils.RemoteIP, NEVER the value
// from X-Forwarded-For or X-Real-IP.
//
// Why not utils.GetIP: when --trusted-proxies is configured GetIP
// walks the X-Forwarded-For chain right-to-left and returns the
// first untrusted hop. Most edge proxies (nginx default, ELB,
// Cloudflare) *append* to X-Forwarded-For rather than replacing it,
// so an attacker who sets X-Forwarded-For: 1.2.3.4 in their request
// gets that value echoed back as the right-most-untrusted hop.
// Rotating header values then cycles bucket keys and defeats the
// rate limit.
//
// Keying on the TCP peer the trusted proxy itself terminates against
// closes the bypass: that address is determined by the proxy's
// network position and is unspoofable from the client side.
func KeyByIP(r *http.Request) string {
	return utils.RemoteIP(r)
}
