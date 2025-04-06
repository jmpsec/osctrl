package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache_SetAndGet(t *testing.T) {
	cache := NewMemoryCache[string]()
	defer cache.Stop()

	ctx := context.Background()

	// Test setting and getting a value
	cache.Set(ctx, "key1", "value1", 0)
	value, found := cache.Get(ctx, "key1")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value1", value, "Expected value to match")

	// Test getting a non-existent key
	_, found = cache.Get(ctx, "nonexistent")
	assert.False(t, found, "Expected not to find the key")
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache := NewMemoryCache[string]()
	defer cache.Stop()

	ctx := context.Background()

	// Set a value with a short expiration
	cache.Set(ctx, "key1", "value1", 50*time.Millisecond)
	value, found := cache.Get(ctx, "key1")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value1", value, "Expected value to match")

	// Wait for the item to expire
	time.Sleep(100 * time.Millisecond)
	_, found = cache.Get(ctx, "key1")
	assert.False(t, found, "Expected not to find the key after expiration")
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache[string]()
	defer cache.Stop()

	ctx := context.Background()

	// Set and delete a value
	cache.Set(ctx, "key1", "value1", 0)
	cache.Delete(ctx, "key1")
	_, found := cache.Get(ctx, "key1")
	assert.False(t, found, "Expected not to find the key after deletion")
}

func TestMemoryCache_Clear(t *testing.T) {
	cache := NewMemoryCache[string]()
	defer cache.Stop()

	ctx := context.Background()

	// Set multiple values and clear the cache
	cache.Set(ctx, "key1", "value1", 0)
	cache.Set(ctx, "key2", "value2", 0)
	cache.Clear(ctx)
	assert.Equal(t, 0, cache.ItemCount(), "Expected cache to be empty after clearing")
}

func TestMemoryCache_ItemCount(t *testing.T) {
	cache := NewMemoryCache[string]()
	defer cache.Stop()

	ctx := context.Background()

	// Test item count
	assert.Equal(t, 0, cache.ItemCount(), "Expected item count to be 0 initially")
	cache.Set(ctx, "key1", "value1", 0)
	assert.Equal(t, 1, cache.ItemCount(), "Expected item count to be 1")
	cache.Set(ctx, "key2", "value2", 0)
	assert.Equal(t, 2, cache.ItemCount(), "Expected item count to be 2")
	cache.Delete(ctx, "key1")
	assert.Equal(t, 1, cache.ItemCount(), "Expected item count to be 1 after deletion")
}

func TestMemoryCache_Options(t *testing.T) {
	// Test WithCleanupInterval option
	customInterval := 10 * time.Second
	cache := NewMemoryCache(WithCleanupInterval[string](customInterval))
	defer cache.Stop()

	assert.Equal(t, customInterval, cache.cleanupInterval, "Expected custom cleanup interval")

	// Test WithName option
	customName := "test-cache"
	cache = NewMemoryCache(WithName[string](customName))
	defer cache.Stop()

	assert.Equal(t, customName, cache.name, "Expected custom cache name")

	// Test multiple options
	cache = NewMemoryCache(WithCleanupInterval[string](customInterval), WithName[string](customName))
	defer cache.Stop()

	assert.Equal(t, customInterval, cache.cleanupInterval, "Expected custom cleanup interval")
	assert.Equal(t, customName, cache.name, "Expected custom cache name")
}

func TestMemoryCache_CleanupRoutine(t *testing.T) {
	// Create cache with short cleanup interval
	cache := NewMemoryCache(WithCleanupInterval[string](100 * time.Millisecond))
	defer cache.Stop()

	ctx := context.Background()

	// Add items with short expiration
	cache.Set(ctx, "key1", "value1", 50*time.Millisecond)
	cache.Set(ctx, "key2", "value2", 50*time.Millisecond)
	cache.Set(ctx, "key3", "value3", 1*time.Hour) // This shouldn't expire

	// Wait for items to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Check that expired items were removed
	_, found := cache.Get(ctx, "key1")
	assert.False(t, found, "Expected key1 to be cleaned up")

	_, found = cache.Get(ctx, "key2")
	assert.False(t, found, "Expected key2 to be cleaned up")

	// Check that non-expired item is still there
	val, found := cache.Get(ctx, "key3")
	assert.True(t, found, "Expected key3 to still exist")
	assert.Equal(t, "value3", val)

	// Verify item count is correct
	assert.Equal(t, 1, cache.ItemCount(), "Expected only one item remaining")
}

func TestMemoryCache_Stop(t *testing.T) {
	cache := NewMemoryCache[string]()

	// We can't easily test the stop functionality directly,
	// but we can at least ensure it doesn't panic
	cache.Stop()

	// Additional stop should panic (channel already closed)
	require.Panics(t, func() {
		cache.Stop()
	})
}

func TestMemoryCache_DifferentTypes(t *testing.T) {
	// Test with int type
	intCache := NewMemoryCache[int]()
	defer intCache.Stop()

	ctx := context.Background()
	intCache.Set(ctx, "number", 42, 0)
	val, found := intCache.Get(ctx, "number")
	assert.True(t, found)
	assert.Equal(t, 42, val)

	// Test with custom struct type
	type Person struct {
		Name string
		Age  int
	}

	structCache := NewMemoryCache[Person]()
	defer structCache.Stop()

	person := Person{Name: "John", Age: 30}
	structCache.Set(ctx, "person", person, 0)

	retrievedPerson, found := structCache.Get(ctx, "person")
	assert.True(t, found)
	assert.Equal(t, person, retrievedPerson)
}
