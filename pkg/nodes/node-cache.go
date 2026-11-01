package nodes

import (
	"context"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/cache"
	"gorm.io/gorm"
)

const (
	cacheName = "nodes"
	// Default time-to-live for cached nodes
	defaultTTL = 60 * time.Minute
	// Default cleanup interval for the cache
	defaultCleanupInterval = 30 * time.Minute
	// redisNodeCacheName prefixes the shared node_key → node entries.
	redisNodeCacheName = "osctrl:nodes:key"
	// redisNodeTTL bounds how long a node changed without Redis (osctrl-cli
	// --db) keeps authenticating with its old key.
	redisNodeTTL = 10 * time.Minute
)

// NodeCache provides cached access to OsqueryNode objects by node_key.
//
// With Redis (osctrl-tls and osctrl-api) the cache is shared, so a node
// deleted or re-enrolled in one process stops authenticating with its old key
// in every process at once. A revoked key is overwritten with a tombstone
// rather than deleted, and misses refill with SetNX, so a reader that loaded
// the row before the change cannot put it back.
type NodeCache struct {
	// The cache itself, storing OsqueryNode objects
	cache      *cache.MemoryCache[OsqueryNode]
	redisCache *cache.RedisJSONCache[OsqueryNode]

	// Reference to the node manager for cache misses
	nodes *NodeManager
}

// NewNodeCache creates a new in-process node cache
func NewNodeCache(nodes *NodeManager) *NodeCache {
	// Create a new cache with appropriate cleanup interval
	nodeCache := cache.NewMemoryCache(
		cache.WithCleanupInterval[OsqueryNode](defaultCleanupInterval),
		cache.WithName[OsqueryNode](cacheName),
	)

	return &NodeCache{
		cache: nodeCache,
		nodes: nodes,
	}
}

// NewRedisNodeCache creates a node cache shared through Redis.
func NewRedisNodeCache(nodes *NodeManager, client *redis.Client) *NodeCache {
	return &NodeCache{
		redisCache: cache.NewRedisJSONCache[OsqueryNode](client, redisNodeCacheName),
		nodes:      nodes,
	}
}

// GetByKey retrieves a node by node_key, using cache when available
func (nc *NodeCache) GetByKey(ctx context.Context, nodeKey string) (OsqueryNode, error) {
	if nc.redisCache != nil {
		node, found, err := nc.redisCache.Get(ctx, nodeKey)
		if err == nil && found {
			if node.ID == 0 {
				// Tombstone: the key was revoked.
				return OsqueryNode{}, gorm.ErrRecordNotFound
			}
			return node, nil
		}
		node, err = nc.nodes.getByKeyFromDB(nodeKey)
		if err != nil {
			return OsqueryNode{}, err
		}
		_ = nc.redisCache.SetNX(ctx, nodeKey, node, redisNodeTTL)
		return node, nil
	}

	// Try to get from cache first
	if node, found := nc.cache.Get(ctx, nodeKey); found {
		return node, nil
	}

	// Not in cache, fetch from database
	node, err := nc.nodes.getByKeyFromDB(nodeKey)
	if err != nil {
		return OsqueryNode{}, err
	}

	// Store in cache for future requests
	nc.cache.Set(ctx, nodeKey, node, defaultTTL)

	return node, nil
}

// InvalidateNode revokes a node_key: callers invoke it after the row behind
// the key changed or was deleted.
func (nc *NodeCache) InvalidateNode(ctx context.Context, nodeKey string) error {
	if nc.redisCache != nil {
		return nc.redisCache.Set(ctx, nodeKey, OsqueryNode{}, redisNodeTTL)
	}
	nc.cache.Delete(ctx, nodeKey)
	return nil
}

// Close stops the cleanup goroutine and releases resources
func (nc *NodeCache) Close() {
	if nc.cache != nil {
		nc.cache.Stop()
	}
}
