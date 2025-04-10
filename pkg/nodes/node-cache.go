package nodes

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/cache"
)

const (
	cacheName = "nodes"
	// Default time-to-live for cached nodes
	defaultTTL = 60 * time.Minute
	// Default cleanup interval for the cache
	defaultCleanupInterval = 30 * time.Minute
)

// NodeCache provides cached access to OsqueryNode objects
type NodeCache struct {
	// The cache itself, storing OsqueryNode objects
	cache *cache.MemoryCache[OsqueryNode]

	// Reference to the node manager for cache misses
	nodes *NodeManager
}

// NewNodeCache creates a new node cache
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

// GetByKey retrieves a node by node_key, using cache when available
func (nc *NodeCache) GetByKey(ctx context.Context, nodeKey string) (OsqueryNode, error) {
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

// InvalidateNode removes a specific node from the cache
func (nc *NodeCache) InvalidateNode(ctx context.Context, nodeKey string) {
	nc.cache.Delete(ctx, nodeKey)
}

// InvalidateAll clears the entire cache
func (nc *NodeCache) InvalidateAll(ctx context.Context) {
	nc.cache.Clear(ctx)
}

// UpdateNodeInCache updates a node in the cache
func (nc *NodeCache) UpdateNodeInCache(ctx context.Context, node OsqueryNode) {
	nc.cache.Set(ctx, node.NodeKey, node, defaultTTL)
}

// Close stops the cleanup goroutine and releases resources
func (nc *NodeCache) Close() {
	if nc.cache != nil {
		nc.cache.Stop()
	}
}
