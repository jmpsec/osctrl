package cache

import (
	"context"
	"sync"
	"time"
)

// Item represents a cached item with expiration
type Item[T any] struct {
	Value      T
	Expiration int64
}

// Cache interface defines methods that any cache implementation must provide
type Cache[T any] interface {
	// Get retrieves an item from the cache by key
	Get(ctx context.Context, key string) (T, bool)

	// Set adds or updates an item in the cache with expiration
	Set(ctx context.Context, key string, value T, duration time.Duration)

	// Delete removes an item from the cache
	Delete(ctx context.Context, key string)

	// Clear removes all items from the cache
	Clear(ctx context.Context)

	// ItemCount returns the number of items in the cache
	ItemCount() int

	// Stop stops the cleanup goroutine
	Stop()
}

// MemoryCacheOption is a function that configures a MemoryCache
type MemoryCacheOption[T any] func(*MemoryCache[T])

// WithCleanupInterval sets the interval for cleaning expired items
func WithCleanupInterval[T any](interval time.Duration) MemoryCacheOption[T] {
	return func(mc *MemoryCache[T]) {
		mc.cleanupInterval = interval
	}
}

// WithName sets the name for the cache instance
func WithName[T any](name string) MemoryCacheOption[T] {
	return func(mc *MemoryCache[T]) {
		mc.name = name
	}
}

// MemoryCache provides an in-memory implementation of the Cache interface
type MemoryCache[T any] struct {
	items           map[string]Item[T]
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	name            string
}

// NewMemoryCache creates a new in-memory cache with the provided options
func NewMemoryCache[T any](opts ...MemoryCacheOption[T]) *MemoryCache[T] {
	cache := &MemoryCache[T]{
		items:           make(map[string]Item[T]),
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
		name:            "default",
	}

	// Apply all provided options
	for _, opt := range opts {
		opt(cache)
	}

	CacheItems.WithLabelValues(cache.name).Set(0)

	// Start cleanup routine to remove expired items
	go cache.cleanupRoutine()

	return cache
}

// Get retrieves an item from the cache
func (c *MemoryCache[T]) Get(ctx context.Context, key string) (T, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, found := c.items[key]
	if !found {
		CacheMisses.WithLabelValues(c.name).Inc()
		var zero T
		return zero, false
	}

	// Check if item has expired
	if item.Expiration > 0 && item.Expiration < time.Now().UnixNano() {
		CacheMisses.WithLabelValues(c.name).Inc()
		var zero T
		return zero, false
	}

	CacheHits.WithLabelValues(c.name).Inc()
	return item.Value, true
}

// Set adds an item to the cache with expiration
func (c *MemoryCache[T]) Set(ctx context.Context, key string, value T, duration time.Duration) {
	var expiration int64

	if duration > 0 {
		expiration = time.Now().Add(duration).UnixNano()
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items[key] = Item[T]{
		Value:      value,
		Expiration: expiration,
	}

	CacheItems.WithLabelValues(c.name).Set(float64(len(c.items)))
}

// Delete removes an item from the cache
func (c *MemoryCache[T]) Delete(ctx context.Context, key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.items, key)

	CacheItems.WithLabelValues(c.name).Set(float64(len(c.items)))
}

// Clear removes all items from the cache
func (c *MemoryCache[T]) Clear(ctx context.Context) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]Item[T])

	CacheItems.WithLabelValues(c.name).Set(0)
}

// ItemCount returns the number of items in the cache
func (c *MemoryCache[T]) ItemCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return len(c.items)
}

// Stop stops the cleanup goroutine
func (c *MemoryCache[T]) Stop() {
	close(c.stopCleanup)
}

// cleanupRoutine periodically cleans up expired items
func (c *MemoryCache[T]) cleanupRoutine() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.deleteExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

// deleteExpired removes expired items from the cache
func (c *MemoryCache[T]) deleteExpired() {
	now := time.Now().UnixNano()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	evictionCount := 0
	for k, v := range c.items {
		if v.Expiration > 0 && v.Expiration < now {
			delete(c.items, k)
			evictionCount++
		}
	}

	if evictionCount > 0 {
		// Update Prometheus metrics for evictions and item count
		CacheEvictions.WithLabelValues(c.name).Add(float64(evictionCount))
		CacheItems.WithLabelValues(c.name).Set(float64(len(c.items)))
	}
}
