package handlers

import (
	"slices"
	"sync"
	"time"

	"github.com/jmpsec/osctrl/pkg/osqueryversions"
)

const (
	// rolloutProgressTTL bounds how stale cached rollout counts can get.
	rolloutProgressTTL = 5 * time.Second
	// rolloutProgressMaxEnvs bounds the number of environments cached.
	rolloutProgressMaxEnvs = 256
)

// rolloutProgressKey makes an entry miss when the rollout row, its effective
// state or its effective stage changes.
type rolloutProgressKey struct {
	rolloutID uint
	state     string
	stage     int
}

type rolloutProgressEntry struct {
	key      rolloutProgressKey
	progress osqueryversions.RolloutProgress
	expires  time.Time
}

// rolloutProgressCache holds the last Progress result per environment, so
// polling the page does not scan every node each time. It is per process:
// mutating handlers invalidate this process's entry, but another API replica
// may serve counts up to rolloutProgressTTL stale after a mutation. The zero
// value is ready to use; errors are never stored.
type rolloutProgressCache struct {
	mu      sync.Mutex
	now     func() time.Time // nil means time.Now, replaced in tests
	entries map[uint]rolloutProgressEntry
}

func (c *rolloutProgressCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *rolloutProgressCache) get(envID uint, key rolloutProgressKey) (osqueryversions.RolloutProgress, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[envID]
	if !ok || e.key != key || !c.clock().Before(e.expires) {
		return osqueryversions.RolloutProgress{}, false
	}
	return cloneProgress(e.progress), true
}

// cloneProgress copies the only reference field, so callers cannot change the cached one.
func cloneProgress(p osqueryversions.RolloutProgress) osqueryversions.RolloutProgress {
	p.RolledBackHosts = slices.Clone(p.RolledBackHosts)
	return p
}

func (c *rolloutProgressCache) put(envID uint, key rolloutProgressKey, p osqueryversions.RolloutProgress) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if c.entries == nil {
		c.entries = make(map[uint]rolloutProgressEntry)
	}
	if _, ok := c.entries[envID]; !ok && len(c.entries) >= rolloutProgressMaxEnvs {
		for id, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, id)
			}
		}
		if len(c.entries) >= rolloutProgressMaxEnvs {
			// ponytail: linear scan of 256 entries; fine at this size.
			var oldest uint
			var oldestAt time.Time
			for id, e := range c.entries {
				if oldestAt.IsZero() || e.expires.Before(oldestAt) {
					oldest, oldestAt = id, e.expires
				}
			}
			delete(c.entries, oldest)
		}
	}
	c.entries[envID] = rolloutProgressEntry{key: key, progress: cloneProgress(p), expires: now.Add(rolloutProgressTTL)}
}

func (c *rolloutProgressCache) invalidate(envID uint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, envID)
}

func (c *rolloutProgressCache) has(envID uint) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[envID]
	return ok
}

func (c *rolloutProgressCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
