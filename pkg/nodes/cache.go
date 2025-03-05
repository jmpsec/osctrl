package nodes

import (
	"context"
	"time"
)

// SetLastSeen sets the last seen fields in the cache for a node
func (n *NodeManager) SetLastSeen(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), map[string]interface{}{
		LastConfig:     node.LastConfig.Format(time.RFC3339),
		LastQueryRead:  node.LastQueryRead.Format(time.RFC3339),
		LastQueryWrite: node.LastQueryWrite.Format(time.RFC3339),
		LastResult:     node.LastResult.Format(time.RFC3339),
		LastStatus:     node.LastStatus.Format(time.RFC3339),
	}).Err()
}

// SetLastConfig sets the last config field in the cache for a node
func (n *NodeManager) SetLastConfig(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), LastConfig, node.LastConfig.Format(time.RFC3339)).Err()
}

// SetLastQueryRead sets the last query read field in the cache for a node
func (n *NodeManager) SetLastQueryRead(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), LastQueryRead, node.LastQueryRead.Format(time.RFC3339)).Err()
}

// SetLastQueryWrite sets the last query write field in the cache for a node
func (n *NodeManager) SetLastQueryWrite(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), LastQueryWrite, node.LastQueryWrite.Format(time.RFC3339)).Err()
}

// SetLastLog sets the last log by type in the cache for a node
// TODO: Use a const for logType once the ciclic dependency is resolved
func (n *NodeManager) SetLastLog(node OsqueryNode, ctx context.Context, logType string) error {
	switch logType {
	case "result":
		return n.SetLastResult(node, ctx)
	case "status":
		return n.SetLastStatus(node, ctx)
	}
	return nil
}

// SetLastResult sets the last result field in the cache for a node
func (n *NodeManager) SetLastResult(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), LastResult, node.LastResult.Format(time.RFC3339)).Err()
}

// SetLastStatus sets the last status field in the cache for a node
func (n *NodeManager) SetLastStatus(node OsqueryNode, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), LastStatus, node.LastStatus.Format(time.RFC3339)).Err()
}

// GetLastSeen returns the last seen fields for a node from the cache
func (n *NodeManager) GetLastSeen(node OsqueryNode, ctx context.Context) (map[string]string, error) {
	return n.Cache.HGetAll(ctx, CacheLastSeenKey(node)).Result()
}

// GetLastSeenField returns a specific last seen field for a node from the cache
func (n *NodeManager) GetLastSeenField(node OsqueryNode, field string, ctx context.Context) (string, error) {
	return n.Cache.HGet(ctx, CacheLastSeenKey(node), field).Result()
}

// SetLastSeenField sets a specific last seen field for a node in the cache
func (n *NodeManager) SetLastSeenField(node OsqueryNode, field, value string, ctx context.Context) error {
	return n.Cache.HSet(ctx, CacheLastSeenKey(node), field, value).Err()
}

// GetLastConfig returns the last config field for a node from the cache
func (n *NodeManager) GetLastConfig(node OsqueryNode, ctx context.Context) (time.Time, error) {
	result, err := n.Cache.HGet(ctx, CacheLastSeenKey(node), LastConfig).Result()
	if err != nil {
		return time.Time{}, err
	}
	return LastSeenTime(result)
}

// GetLastQueryRead returns the last query read field for a node from the cache
func (n *NodeManager) GetLastQueryRead(node OsqueryNode, ctx context.Context) (time.Time, error) {
	result, err := n.Cache.HGet(ctx, CacheLastSeenKey(node), LastQueryRead).Result()
	if err != nil {
		return time.Time{}, err
	}
	return LastSeenTime(result)
}

// GetLastQueryWrite returns the last query write field for a node from the cache
func (n *NodeManager) GetLastQueryWrite(node OsqueryNode, ctx context.Context) (time.Time, error) {
	result, err := n.Cache.HGet(ctx, CacheLastSeenKey(node), LastQueryWrite).Result()
	if err != nil {
		return time.Time{}, err
	}
	return LastSeenTime(result)
}

// GetLastResult returns the last result field for a node from the cache
func (n *NodeManager) GetLastResult(node OsqueryNode, ctx context.Context) (time.Time, error) {
	result, err := n.Cache.HGet(ctx, CacheLastSeenKey(node), LastResult).Result()
	if err != nil {
		return time.Time{}, err
	}
	return LastSeenTime(result)
}

// GetLastStatus returns the last status field for a node from the cache
func (n *NodeManager) GetLastStatus(node OsqueryNode, ctx context.Context) (time.Time, error) {
	result, err := n.Cache.HGet(ctx, CacheLastSeenKey(node), LastStatus).Result()
	if err != nil {
		return time.Time{}, err
	}
	return LastSeenTime(result)
}
