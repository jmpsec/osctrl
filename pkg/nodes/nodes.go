package nodes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	// ActiveNodes to represent active nodes
	ActiveNodes = "active"
	// InactiveNodes to represent inactive nodes
	InactiveNodes = "inactive"
	// AllNodes to represent all nodes
	AllNodes = "all"
	// EnvSelector to represent environment selector
	EnvironmentSelector = "environment"
	// PlatformSelector to represent platform selector
	PlatformSelector = "platform"
)

// StatsData to display node stats
type StatsData struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Inactive int64 `json:"inactive"`
}

// NodeManager to handle all nodes of the system
type NodeManager struct {
	DB    *gorm.DB
	Cache *NodeCache
}

// CreateNodes to initialize the nodes struct and its tables
func CreateNodes(backend *gorm.DB) *NodeManager {
	var n *NodeManager = &NodeManager{
		DB: backend,
	}
	// table osquery_nodes
	if err := backend.AutoMigrate(&OsqueryNode{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (osquery_nodes): %v", err)
	}
	// table archive_osquery_nodes
	if err := backend.AutoMigrate(&ArchiveOsqueryNode{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (archive_osquery_nodes): %v", err)
	}
	// Create and initialize the cache
	n.Cache = NewNodeCache(n)
	return n
}

// CheckByUUID to check if node exists by UUID
// UUID is expected uppercase
func (n *NodeManager) CheckByUUID(uuid string) bool {
	var results int64
	n.DB.Model(&OsqueryNode{}).Where("uuid = ?", strings.ToUpper(uuid)).Count(&results)
	return (results > 0)
}

// CheckByUUIDEnv to check if node exists by UUID in a specific environment
// UUID is expected uppercase
func (n *NodeManager) CheckByUUIDEnv(uuid, environment string) bool {
	var results int64
	n.DB.Model(&OsqueryNode{}).Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Count(&results)
	return (results > 0)
}

// CheckByHost to check if node exists by Hostname
func (n *NodeManager) CheckByHost(host string) bool {
	var results int64
	n.DB.Model(&OsqueryNode{}).Where("hostname = ? OR localname = ?", host, host).Count(&results)
	return (results > 0)
}

// getByKeyFromDB to retrieve full node object directly from DB, by node_key
// This is used by the cache system on cache misses
// node_key is expected lowercase
func (n *NodeManager) getByKeyFromDB(nodekey string) (OsqueryNode, error) {
	var node OsqueryNode
	if err := n.DB.Where("node_key = ?", strings.ToLower(nodekey)).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// GetByKey to retrieve full node object from DB or cache, by node_key
// node_key is expected lowercase
func (n *NodeManager) GetByKey(nodekey string) (OsqueryNode, error) {
	// Currently, the the cache would not be updated frequently
	// It should only be used for fetching the node object that is rarely updated
	return n.Cache.GetByKey(context.Background(), strings.ToLower(nodekey))
}

// GetByIdentifier to retrieve full node object from DB, by uuid or hostname or localname
// UUID is expected uppercase
func (n *NodeManager) GetByIdentifier(identifier string) (OsqueryNode, error) {
	var node OsqueryNode
	if err := n.DB.Where(
		"uuid = ? OR hostname = ? OR localname = ?",
		strings.ToUpper(identifier),
		identifier,
		identifier,
	).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// GetByIdentifierEnv to retrieve full node object from DB, by uuid or hostname or localname
// UUID is expected uppercase
func (n *NodeManager) GetByIdentifierEnv(identifier string, envid uint) (OsqueryNode, error) {
	var node OsqueryNode
	if err := n.DB.Where(
		"(uuid = ? OR hostname = ? OR localname = ?) AND environment_id = ?",
		strings.ToUpper(identifier),
		identifier,
		identifier,
		envid,
	).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// GetByUUID to retrieve full node object from DB, by uuid
// UUID is expected uppercase
func (n *NodeManager) GetByUUID(uuid string) (OsqueryNode, error) {
	var node OsqueryNode
	if err := n.DB.Where("uuid = ?", strings.ToUpper(uuid)).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// GetByUUIDEnv to retrieve full node object from DB, by uuid and environment ID
// UUID is expected uppercase
func (n *NodeManager) GetByUUIDEnv(uuid string, envid uint) (OsqueryNode, error) {
	var node OsqueryNode
	if err := n.DB.Where("uuid = ? AND environment_id = ?", strings.ToUpper(uuid), envid).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// GetBySelector to retrieve target nodes by selector
func (n *NodeManager) GetBySelector(stype, selector, target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	var column string
	switch stype {
	case EnvironmentSelector:
		column = EnvironmentSelector
	case PlatformSelector:
		column = PlatformSelector
	default:
		return nodes, fmt.Errorf("invalid selector type: %s", stype)
	}
	// Build query with base condition
	query := n.DB.Where(column+" = ?", selector)
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// Gets to retrieve all/active/inactive nodes
func (n *NodeManager) Gets(target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	// Start with base query
	query := n.DB
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// GetByEnv to retrieve target nodes by environment
func (n *NodeManager) GetByEnv(env, target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	// Build query with base condition
	query := n.DB.Where("environment = ?", env)
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// GetByEnvLimit to retrieve target nodes by environment with limit and offset
func (n *NodeManager) GetByEnvLimit(env, target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	// Build query with base condition
	query := n.DB.Where("environment = ?", env)
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// SearchByEnv to search nodes by environment and search term
func (n *NodeManager) SearchByEnv(env, term, target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	likeTerm := "%" + term + "%"
	// Build query with base condition
	query := n.DB.Where("environment = ? AND (uuid LIKE ? OR hostname LIKE ? OR localname LIKE ? OR ip_address LIKE ? OR username LIKE ? OR osquery_user LIKE ? OR platform LIKE ? OR osquery_version LIKE ?)", env, likeTerm, likeTerm, likeTerm, likeTerm, likeTerm, likeTerm, likeTerm, likeTerm)
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// GetByPlatform to retrieve target nodes by platform
func (n *NodeManager) GetByPlatform(envID uint, platform, target string, hours int64) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	// Build query with base condition
	query := n.DB.Where("platform = ? AND environment_id = ?", platform, envID)
	// Apply active/inactive filtering
	query = ApplyNodeTarget(query, target, hours)
	// Execute query
	if err := query.Find(&nodes).Error; err != nil {
		return nodes, err
	}
	return nodes, nil
}

// GetAllPlatforms to get all different platform with nodes in them
func (n *NodeManager) GetAllPlatforms() ([]string, error) {
	var platforms []string
	var platform string
	rows, err := n.DB.Table("osquery_nodes").Select("DISTINCT(platform)").Rows()
	if err != nil {
		return platforms, nil
	}
	for rows.Next() {
		_ = rows.Scan(&platform)
		platforms = append(platforms, platform)
	}
	return platforms, nil
}

// GetEnvPlatforms to get the platforms with nodes in them by environment
func (n *NodeManager) GetEnvPlatforms(environment string) ([]string, error) {
	var platforms []string
	var platform string
	rows, err := n.DB.Table("osquery_nodes").Select("DISTINCT(platform)").Where("environment = ?", environment).Rows()
	if err != nil {
		return platforms, nil
	}
	for rows.Next() {
		_ = rows.Scan(&platform)
		platforms = append(platforms, platform)
	}
	return platforms, nil
}

// GetEnvIDPlatforms to get the platforms with nodes in them by environment
func (n *NodeManager) GetEnvIDPlatforms(envID uint) ([]string, error) {
	var platforms []string
	var platform string
	rows, err := n.DB.Table("osquery_nodes").Select("DISTINCT(platform)").Where("environment_id = ?", envID).Rows()
	if err != nil {
		return platforms, nil
	}
	for rows.Next() {
		_ = rows.Scan(&platform)
		platforms = append(platforms, platform)
	}
	return platforms, nil
}

// GetStatsByEnv to populate table stats about nodes by environment
func (n *NodeManager) GetStatsByEnv(environment string, hours int64) (StatsData, error) {
	return GetStats(n.DB, EnvironmentSelector, environment, hours)
}

// UpdateMetadataByUUID to update node metadata by UUID
func (n *NodeManager) UpdateMetadataByUUID(uuid string, metadata NodeMetadata) error {
	// Retrieve node
	node, err := n.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %w", err)
	}
	// Prepare metadata updates
	updates := map[string]interface{}{
		"bytes_received": node.BytesReceived + metadata.BytesReceived,
	}
	// Record username
	if metadata.Username != node.Username && metadata.Username != "" {
		updates["username"] = metadata.Username
	}
	// Record hostname
	if metadata.Hostname != node.Hostname && metadata.Hostname != "" {
		updates["hostname"] = metadata.Hostname
	}
	// Record localname
	if metadata.Localname != node.Localname && metadata.Localname != "" {
		updates["localname"] = metadata.Localname
	}
	// Record IP address
	if metadata.IPAddress != node.IPAddress && metadata.IPAddress != "" {
		updates["ip_address"] = metadata.IPAddress
	}
	// Configuration and daemon hash and osquery version update, if different
	if metadata.ConfigHash != node.ConfigHash && metadata.ConfigHash != "" {
		updates["config_hash"] = metadata.ConfigHash
	}
	if metadata.DaemonHash != node.DaemonHash && metadata.DaemonHash != "" {
		updates["daemon_hash"] = metadata.DaemonHash
	}
	if metadata.OsqueryVersion != node.OsqueryVersion && metadata.OsqueryVersion != "" {
		updates["osquery_version"] = metadata.OsqueryVersion
	}
	if metadata.OsqueryUser != node.OsqueryUser && metadata.OsqueryUser != "" {
		updates["osquery_user"] = metadata.OsqueryUser
	}
	if err := n.MetadataRefresh(node, updates); err != nil {
		return fmt.Errorf("MetadataRefresh %w", err)
	}
	return nil
}

// Create to insert new osquery node generating new node_key
func (n *NodeManager) Create(node *OsqueryNode) error {
	if err := n.DB.Create(&node).Error; err != nil {
		return fmt.Errorf("create %w", err)
	}
	return nil
}

// NewHistoryEntry to insert new entry for the history of Hostnames
func (n *NodeManager) NewHistoryEntry(entry interface{}) error {
	if err := n.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("create newNodeHistoryEntry %w", err)
	}
	return nil
}

// Archive to archive osquery node by UUID
func (n *NodeManager) Archive(uuid, trigger string) error {
	node, err := n.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %w", err)
	}
	archivedNode := nodeArchiveFromNode(node, trigger)
	if err := n.DB.Create(&archivedNode).Error; err != nil {
		return fmt.Errorf("error in Create %w", err)
	}
	return nil
}

// UpdateByUUID to update an existing node record by UUID
func (n *NodeManager) UpdateByUUID(data OsqueryNode, uuid string) error {
	node, err := n.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %w", err)
	}
	if err := n.DB.Model(&node).Updates(data).Error; err != nil {
		return fmt.Errorf("error in UpdateByUUID %w", err)
	}
	return nil
}

// ArchiveDeleteByUUID to archive and delete an existing node record by UUID
func (n *NodeManager) ArchiveDeleteByUUID(uuid string) error {
	node, err := n.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %w", err)
	}
	archivedNode := nodeArchiveFromNode(node, "delete")
	if err := n.DB.Create(&archivedNode).Error; err != nil {
		return fmt.Errorf("create %w", err)
	}
	if err := n.DB.Unscoped().Delete(&node).Error; err != nil {
		return fmt.Errorf("delete %w", err)
	}
	return nil
}

// Helper to convert an enrolled osquery node into an archived osquery node
func nodeArchiveFromNode(node OsqueryNode, trigger string) ArchiveOsqueryNode {
	return ArchiveOsqueryNode{
		NodeKey:         node.NodeKey,
		UUID:            node.UUID,
		Trigger:         trigger,
		Platform:        node.Platform,
		PlatformVersion: node.PlatformVersion,
		OsqueryVersion:  node.OsqueryVersion,
		Hostname:        node.Hostname,
		Localname:       node.Localname,
		IPAddress:       node.IPAddress,
		Username:        node.Username,
		OsqueryUser:     node.OsqueryUser,
		Environment:     node.Environment,
		CPU:             node.CPU,
		Memory:          node.Memory,
		HardwareSerial:  node.HardwareSerial,
		DaemonHash:      node.DaemonHash,
		ConfigHash:      node.ConfigHash,
		BytesReceived:   node.BytesReceived,
		RawEnrollment:   node.RawEnrollment,
		LastSeen:        node.LastSeen,
		UserID:          node.UserID,
		EnvironmentID:   node.EnvironmentID,
		ExtraData:       node.ExtraData,
	}
}

// IncreaseBytes to update received bytes per node
func (n *NodeManager) IncreaseBytes(node OsqueryNode, incBytes int) error {
	if err := n.DB.Model(&node).Update("bytes_received", node.BytesReceived+incBytes).Error; err != nil {
		return fmt.Errorf("update bytes_received - %w", err)
	}
	return nil
}

func (n *NodeManager) RefreshLastSeenBatch(nodeID []uint) error {

	return n.DB.Model(&OsqueryNode{}).Where("id IN ?", nodeID).UpdateColumn("last_seen", time.Now()).Error
}

func (n *NodeManager) UpdateIP(nodeID uint, ip string) error {
	// Update the IP address in the database
	return n.DB.Model(&OsqueryNode{}).Where("id = ?", nodeID).UpdateColumn("ip_address", ip).Error

}

// MetadataRefresh to perform all needed update operations per node to keep metadata refreshed
func (n *NodeManager) MetadataRefresh(node OsqueryNode, updates map[string]interface{}) error {
	return n.DB.Model(&node).Updates(updates).Error
}

// CountAll to count all nodes
func (n *NodeManager) CountAll() (int64, error) {
	var count int64
	if err := n.DB.Model(&OsqueryNode{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count all %w", err)
	}
	return count, nil
}

// CountAllByEnv to count all nodes
func (n *NodeManager) CountAllByEnv(envID uint) (int64, error) {
	var count int64
	if err := n.DB.Model(&OsqueryNode{}).Where("environment_id = ?", envID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count all %w", err)
	}
	return count, nil
}
