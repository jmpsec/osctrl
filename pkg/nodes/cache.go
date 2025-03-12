package nodes

import (
	"context"
	"strconv"
	"time"
)

// Keys to identify the node fields in the cache
const (
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
)

// SetCached sets the provided node in the cache, default expiration is 3 hours
func (n *NodeManager) SetCached(node OsqueryNode, ctx context.Context) error {
	k := CacheKey(node)
	if err := n.Cache.HSet(ctx, k, map[string]interface{}{
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
	}).Err(); err != nil {
		return err
	}
	return n.Cache.ExpireAt(ctx, k, time.Now().Add(1*time.Hour)).Err()
}

// GetFromCache returns the node from the cache by node UUID and environment ID
func (n *NodeManager) GetFromCache(uuid string, envID uint, ctx context.Context) (OsqueryNode, error) {
	var node OsqueryNode
	res, err := n.Cache.HGetAll(ctx, CacheKeyRaw(uuid, envID)).Result()
	if err != nil {
		return node, err
	}
	node.CreatedAt, err = time.Parse(time.RFC3339, res[kCreated])
	if err != nil {
		node.CreatedAt = time.Time{}
	}
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
	if err != nil {
		resEnvID = 0
	}
	node.EnvironmentID = uint(resEnvID)
	node.HardwareSerial = res[kHardwareSerial]
	node.CPU = res[kCPU]
	node.Memory = res[kMemory]

	return node, nil
}
