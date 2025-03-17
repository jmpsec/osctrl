package nodes

import (
	"context"
	"math"
	"strconv"
	"time"
)

// Keys to identify the node fields in the cache
const (
	kID              = "id"
	kCreated         = "created_at"
	kNodeKey         = "node_key"
	kUUID            = "uuid"
	kPlatform        = "platform"
	kPlatformVersion = "platform_version"
	kOsqueryVersion  = "osquery_version"
	kHostname        = "hostname"
	kIPAddress       = "ip_address"
	kLocalname       = "localname"
	kUsername        = "username"
	kOsqueryUser     = "osquery_user"
	kEnvironment     = "environment"
	kEnvironmentID   = "environment_id"
	kHardwareSerial  = "hardware_serial"
	kCPU             = "cpu"
	kMemory          = "memory"
	kLastSeen        = "last_seen"
	kBytesReceived   = "bytes_received"
)

// SetFullCached sets the provided full node in the cache, default expiration is 1 hour
func (n *NodeManager) SetFullCached(node OsqueryNode, ctx context.Context) error {
	k := CacheFullKeyByUUID(node)
	if err := n.Cache.HSet(ctx, k, map[string]interface{}{
		kID:              node.ID,
		kCreated:         node.CreatedAt.Format(time.RFC3339),
		kNodeKey:         node.NodeKey,
		kUUID:            node.UUID,
		kPlatform:        node.Platform,
		kPlatformVersion: node.PlatformVersion,
		kOsqueryVersion:  node.OsqueryVersion,
		kHostname:        node.Hostname,
		kIPAddress:       node.IPAddress,
		kLocalname:       node.Localname,
		kUsername:        node.Username,
		kOsqueryUser:     node.OsqueryUser,
		kEnvironment:     node.Environment,
		kEnvironmentID:   node.EnvironmentID,
		kHardwareSerial:  node.HardwareSerial,
		kCPU:             node.CPU,
		kMemory:          node.Memory,
		kLastSeen:        time.Now().Format(time.RFC3339),
		kBytesReceived:   node.BytesReceived,
	}).Err(); err != nil {
		return err
	}
	return n.Cache.ExpireAt(ctx, k, time.Now().Add(1*time.Hour)).Err()
}

// SetPartialCached sets the provided partial node in the cache, default expiration is 1 hour
func (n *NodeManager) SetPartialCached(node OsqueryNode, ctx context.Context) error {
	k := CachePartialKeyByNodeKey(node)
	if err := n.Cache.HSet(ctx, k, map[string]interface{}{
		kID:        node.ID,
		kNodeKey:   node.NodeKey,
		kUUID:      node.UUID,
		kIPAddress: node.IPAddress,
	}).Err(); err != nil {
		return err
	}
	return n.Cache.ExpireAt(ctx, k, time.Now().Add(1*time.Hour)).Err()
}

// GetFullFromCache returns the full node from the cache by node UUID and environment ID
func (n *NodeManager) GetFullFromCache(uuid string, envID uint, ctx context.Context) (OsqueryNode, error) {
	var node OsqueryNode
	res, err := n.Cache.HGetAll(ctx, CacheFullKeyRaw(uuid, envID)).Result()
	if err != nil {
		return node, err
	}
	node.CreatedAt, err = time.Parse(time.RFC3339, res[kCreated])
	if err != nil {
		node.CreatedAt = time.Time{}
	}
	node.LastSeen, err = time.Parse(time.RFC3339, res[kLastSeen])
	if err != nil {
		node.LastSeen = time.Time{}
	}
	resID, err := strconv.ParseUint(res[kID], 10, 32)
	if err != nil || resID > math.MaxInt {
		node.ID = 0
	}
	node.ID = uint(resID)
	node.NodeKey = res[kNodeKey]
	node.UUID = res[kUUID]
	node.Platform = res[kPlatform]
	node.PlatformVersion = res[kPlatformVersion]
	node.OsqueryVersion = res[kOsqueryVersion]
	node.Hostname = res[kHostname]
	node.IPAddress = res[kIPAddress]
	node.Localname = res[kLocalname]
	node.Username = res[kUsername]
	node.OsqueryUser = res[kOsqueryUser]
	node.Environment = res[kEnvironment]
	resEnvID, err := strconv.ParseUint(res[kEnvironmentID], 10, 32)
	if err != nil || resEnvID > math.MaxInt {
		resEnvID = 0
	}
	node.EnvironmentID = uint(resEnvID)
	node.HardwareSerial = res[kHardwareSerial]
	node.CPU = res[kCPU]
	node.Memory = res[kMemory]
	resBytes, err := strconv.ParseInt(res[kBytesReceived], 10, 32)
	if err != nil || resBytes > math.MaxInt {
		resBytes = 0
	}
	node.BytesReceived = int(resBytes)
	return node, nil
}

// GetPartialFromCache returns the partial node from the cache by node key and environment ID
func (n *NodeManager) GetPartialFromCache(nodeKey string, envID uint, ctx context.Context) (OsqueryNode, error) {
	var node OsqueryNode
	res, err := n.Cache.HGetAll(ctx, CachePartialKeyRaw(nodeKey, envID)).Result()
	if err != nil {
		return node, err
	}
	resID, err := strconv.ParseUint(res[kID], 10, 32)
	if err != nil || resID > math.MaxInt {
		node.ID = 0
	}
	node.ID = uint(resID)
	node.NodeKey = res[kNodeKey]
	node.UUID = res[kUUID]
	node.IPAddress = res[kIPAddress]
	return node, nil
}
