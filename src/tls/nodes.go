package main

import (
	"fmt"
	"net"
	"time"
)

// Check if node exists by node_key
func checkNodeByKey(nodeKey string) bool {
	var results int
	db.Model(&OsqueryNode{}).Where("node_key = ?", nodeKey).Count(&results)
	return (results > 0)
}

// Check if node exists by UUID
func checkNodeByUUID(UUID string) bool {
	var results int
	db.Model(&OsqueryNode{}).Where("uuid = ?", UUID).Count(&results)
	return (results > 0)
}

// Retrieve full node object from DB, by node_key
func getNodeByKey(nodekey string) (OsqueryNode, error) {
	var node OsqueryNode
	if err := db.Where("node_key = ?", nodekey).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// Retrieve full node object from DB, by uuid
func getNodeByUUID(UUID string) (OsqueryNode, error) {
	var node OsqueryNode
	if err := db.Where("uuid = ?", UUID).First(&node).Error; err != nil {
		return node, err
	}
	return node, nil
}

// Retrieve target nodes by selector
func getNodesBySelector(stype, selector, target string) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	var s string
	switch stype {
	case "context":
		s = "context"
	case "platform":
		s = "platform"
	}
	switch target {
	case "all":
		if err := db.Where(s+" = ?", selector).Find(&nodes).Error; err != nil {
			return nodes, err
		}
	case "active":
		if err := db.Where(s+" = ?", selector).Where("updated_at > ?", time.Now().AddDate(0, 0, -3)).Find(&nodes).Error; err != nil {
			return nodes, err
		}
	case "inactive":
		if err := db.Where(s+" = ?", selector).Where("updated_at < ?", time.Now().AddDate(0, 0, -3)).Find(&nodes).Error; err != nil {
			return nodes, err
		}
	}
	return nodes, nil
}

// Retrieve all/active/inactive nodes
func getNodes(target string) ([]OsqueryNode, error) {
	var nodes []OsqueryNode
	switch target {
	case "all":
		if err := db.Find(&nodes).Error; err != nil {
			return nodes, err
		}
	case "active":
		if err := db.Where("updated_at > ?", time.Now().AddDate(0, 0, -3)).Find(&nodes).Error; err != nil {
			return nodes, err
		}
	case "inactive":
		if err := db.Where("updated_at < ?", time.Now().AddDate(0, 0, -3)).Find(&nodes).Error; err != nil {
			return nodes, err
		}
	}
	return nodes, nil
}

// Retrieve target nodes by context
func getNodesByContext(context, target string) ([]OsqueryNode, error) {
	return getNodesBySelector("context", context, target)
}

// Retrieve target nodes by platform
func getNodesByPlatform(platform, target string) ([]OsqueryNode, error) {
	return getNodesBySelector("platform", platform, target)
}

// Get all different platform with nodes in them
func getAllPlatforms() ([]string, error) {
	var platforms []string
	var platform string
	rows, err := db.Table("osquery_nodes").Select("DISTINCT(platform)").Rows()
	if err != nil {
		return platforms, nil
	}
	for rows.Next() {
		rows.Scan(&platform)
		platforms = append(platforms, platform)
	}
	return platforms, nil
}

// Table stats about nodes by context. Active machine is < 3 days
func getNodeStatsByContext(context string) (NodeStats, error) {
	var stats NodeStats
	if err := db.Model(&OsqueryNode{}).Where("context = ?", context).Count(&stats.Total).Error; err != nil {
		return stats, err
	}
	if err := db.Model(&OsqueryNode{}).Where("context = ?", context).Where("updated_at > ?", time.Now().AddDate(0, 0, -3)).Count(&stats.Active).Error; err != nil {
		return stats, err
	}
	if err := db.Model(&OsqueryNode{}).Where("context = ?", context).Where("updated_at < ?", time.Now().AddDate(0, 0, -3)).Count(&stats.Inactive).Error; err != nil {
		return stats, err
	}
	return stats, nil
}

// Table stats about nodes by platform. Active machine is < 3 days
func getNodeStatsByPlatform(platform string) (NodeStats, error) {
	var stats NodeStats
	if err := db.Model(&OsqueryNode{}).Where("platform = ?", platform).Count(&stats.Total).Error; err != nil {
		return stats, err
	}
	if err := db.Model(&OsqueryNode{}).Where("platform = ?", platform).Where("updated_at > ?", time.Now().AddDate(0, 0, -3)).Count(&stats.Active).Error; err != nil {
		return stats, err
	}
	if err := db.Model(&OsqueryNode{}).Where("platform = ?", platform).Where("updated_at < ?", time.Now().AddDate(0, 0, -3)).Count(&stats.Inactive).Error; err != nil {
		return stats, err
	}
	return stats, nil
}

// Update node metadata by UUID
func updateMetadataByUUID(user, osqueryuser, hostname, localname, ipaddress, confighash, osqueryversion, UUID string) error {
	// Retireve node
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	// Prepare data
	data := OsqueryNode{
		OsqueryUser:    "",
		Username:       "",
		Hostname:       "",
		Localname:      "",
		IPAddress:      "",
		ConfigHash:     "",
		OsqueryVersion: "",
	}
	// System user metadata update, if different
	if (user != "") && (user != node.Username) {
		data.Username = user
		e := NodeHistoryUsername{
			UUID:     node.UUID,
			Username: user,
		}
		if err := newNodeHistoryUsername(e); err != nil {
			return fmt.Errorf("newNodeHistoryUsername %v", err)
		}
	}
	// Osquery user metadata update, if different
	if (osqueryuser != "") && (osqueryuser != node.OsqueryUser) {
		data.OsqueryUser = osqueryuser
	}
	// Hostname metadata update, if different
	if (hostname != "") && (hostname != node.Hostname) {
		data.Hostname = hostname
		e := NodeHistoryHostname{
			UUID:     node.UUID,
			Hostname: hostname,
		}
		if err := newNodeHistoryHostname(e); err != nil {
			return fmt.Errorf("newNodeHistoryHostname %v", err)
		}
	}
	// Localname metadata update, if different
	if (localname != "") && (localname != node.Localname) {
		data.Localname = localname
		e := NodeHistoryLocalname{
			UUID:      node.UUID,
			Localname: localname,
		}
		if err := newNodeHistoryLocalname(e); err != nil {
			return fmt.Errorf("newNodeHistoryLocalname %v", err)
		}
	}
	// IP Address metadata update, if different
	if (ipaddress != "") && (ipaddress != node.IPAddress) {
		data.IPAddress = ipaddress
		e := NodeHistoryIPAddress{
			UUID:      node.UUID,
			IPAddress: ipaddress,
			Count:     1,
		}
		if err := newNodeHistoryIPAddress(e); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
	} else {
		if err := incNodeHistoryIPAddress(node.UUID, ipaddress); err != nil {
			return fmt.Errorf("incNodeHistoryIPAddress %v", err)
		}
	}
	// IP Address geo location, if IP is public and Geo Location enabled
	if err := geoLocationCheckByIPAddress(ipaddress); err != nil {
		return fmt.Errorf("geoLocationCheckByIPAddress %v", err)
	}
	// Osquery configuration metadata update, if different
	if (confighash != "") && (confighash != node.ConfigHash) {
		data.ConfigHash = confighash
	}
	// Osquery version metadata update, if different
	if (osqueryversion != "") && (osqueryversion != node.OsqueryVersion) {
		data.OsqueryVersion = osqueryversion
	}
	if err := db.Model(&node).Updates(data).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// Update node IP Address by Node
func updateIPAddressByNode(ipaddress string, node OsqueryNode) error {
	data := OsqueryNode{
		IPAddress: "",
	}
	if (ipaddress != "") && (ipaddress != node.IPAddress) {
		data.IPAddress = ipaddress
		e := NodeHistoryIPAddress{
			UUID:      node.UUID,
			IPAddress: ipaddress,
			Count:     1,
		}
		if err := newNodeHistoryIPAddress(e); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
		if err := db.Model(&node).Updates(data).Error; err != nil {
			return fmt.Errorf("Updates %v", err)
		}
	} else {
		if err := incNodeHistoryIPAddress(node.UUID, ipaddress); err != nil {
			return fmt.Errorf("incNodeHistoryIPAddress %v", err)
		}
		if err := db.Model(&node).Update("updated_at", time.Now()).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	// IP Address geo location, if IP is public and Geo Location enabled
	if err := geoLocationCheckByIPAddress(ipaddress); err != nil {
		return fmt.Errorf("geoLocationCheckByIPAddress %v", err)
	}
	return nil
}

// Update node IP Address by UUID
func updateIPAddressByUUID(ipaddress, UUID string) error {
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	return updateIPAddressByNode(ipaddress, node)
}

// Update node IP Address by node_key
func updateIPAddressByKey(ipaddress, nodekey string) error {
	node, err := getNodeByKey(nodekey)
	if err != nil {
		return fmt.Errorf("getNodeByKey %v", err)
	}
	return updateIPAddressByNode(ipaddress, node)
}

// Insert new osquery node generating new node_key
func createOsqueryNode(node OsqueryNode) error {
	if db.NewRecord(node) {
		if err := db.Create(&node).Error; err != nil {
			return fmt.Errorf("Create %v", err)
		}
		h := NodeHistoryHostname{
			UUID:     node.UUID,
			Hostname: node.Hostname,
		}
		if err := newNodeHistoryHostname(h); err != nil {
			return fmt.Errorf("newNodeHistoryHostname %v", err)
		}
		l := NodeHistoryLocalname{
			UUID:      node.UUID,
			Localname: node.Localname,
		}
		if err := newNodeHistoryLocalname(l); err != nil {
			return fmt.Errorf("newNodeHistoryLocalname %v", err)
		}
		i := NodeHistoryIPAddress{
			UUID:      node.UUID,
			IPAddress: node.IPAddress,
			Count:     1,
		}
		if err := newNodeHistoryIPAddress(i); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
		if err := geoLocationCheckByIPAddress(node.IPAddress); err != nil {
			return fmt.Errorf("geoLocationCheckByIPAddress %v", err)
		}
		u := NodeHistoryUsername{
			UUID:     node.UUID,
			Username: node.Username,
		}
		if err := newNodeHistoryUsername(u); err != nil {
			return fmt.Errorf("newNodeHistoryUsername %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Insert new entry for the history of Hostnames
func newNodeHistoryEntry(entry interface{}) error {
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create newNodeHistoryEntry %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Insert new entry for the history of Hostnames
func newNodeHistoryHostname(entry NodeHistoryHostname) error {
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create newNodeHistoryHostname %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Insert new entry for the history of Localnames
func newNodeHistoryLocalname(entry NodeHistoryLocalname) error {
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create newNodeHistoryLocalname %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Insert new entry for the history of Usernames
func newNodeHistoryUsername(entry NodeHistoryUsername) error {
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			return fmt.Errorf("Create newNodeHistoryUsername %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Insert new entry for the history of IP Addresses
func newNodeHistoryIPAddress(entry NodeHistoryIPAddress) error {
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// If IP Address is not already stored, request the API and save it
func geoLocationCheckByIPAddress(ipaddress string) error {
	// IP Address geo location, if IP is public and geolocation is enabled
	if isPublicIP(net.ParseIP(ipaddress)) && geolocConfig.Maps {
		// Check if data is already mapped
		// FIXME check how old is the data, and maybe refresh if older than some time
		if !checkGeoLocationIPAddress(ipaddress) {
			// Retrieve new data
			newLoc, err := getIPStackData(ipaddress, geolocConfig.IPStackCfg)
			if err != nil {
				return fmt.Errorf("getIPStackData %v", err)
			}
			// Create entry in geo location table
			if err := newGeoLocationIPAddress(newLoc); err != nil {
				return fmt.Errorf("newGeoLocationIPAddress %v", err)
			}
		}
	}
	return nil
}

// Insert new entry for the geo location of an IP Address
func newGeoLocationIPAddress(geoloc GeoLocationIPAddress) error {
	if db.NewRecord(geoloc) {
		if err := db.Create(&geoloc).Error; err != nil {
			return fmt.Errorf("Create newGeoLocationIPAddress %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Check if IP Address is already mapped for Geo Location
func checkGeoLocationIPAddress(ipaddress string) bool {
	var results int
	db.Model(&GeoLocationIPAddress{}).Where("ip_address = ?", ipaddress).Count(&results)
	return (results > 0)
}

// Retrieve geo location data by IP Address
func getGeoLocationIPAddress(ipaddress string) (GeoLocationIPAddress, error) {
	var geoloc GeoLocationIPAddress
	if err := db.Where("ip_address = ?", ipaddress).Order("updated_at").First(&geoloc).Error; err != nil {
		return geoloc, err
	}
	return geoloc, nil
}

// Retrieve the History IP Address record by UUID and the IP Address
func getNodeHistoryIPAddress(UUID, ipaddress string) (NodeHistoryIPAddress, error) {
	var nodeip NodeHistoryIPAddress
	if err := db.Where("uuid = ? AND ip_address = ?", UUID, ipaddress).Order("updated_at").First(&nodeip).Error; err != nil {
		return nodeip, err
	}
	return nodeip, nil
}

// Increase the count for this IP Address
func incNodeHistoryIPAddress(UUID, ipaddress string) error {
	nodeip, err := getNodeHistoryIPAddress(UUID, ipaddress)
	if err != nil {
		return fmt.Errorf("getNodeHistoryIPAddress %v", err)
	}
	if err := db.Model(&nodeip).Update("count", nodeip.Count+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// Archive osquery node by UUID
func archiveOsqueryNode(UUID, trigger string) error {
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	archivedNode := nodeArchiveFromNode(node, trigger)
	if db.NewRecord(archivedNode) {
		if err := db.Create(&archivedNode).Error; err != nil {
			return fmt.Errorf("Create %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Update an existing node record by UUID
func updateOsqueryNodeByUUID(data OsqueryNode, UUID string) error {
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	if err := db.Model(&node).Updates(data).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// Archive and delete an existing node record by UUID
func archiveDeleteOsqueryNodeByUUID(UUID string) error {
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	archivedNode := nodeArchiveFromNode(node, "delete")
	if db.NewRecord(archivedNode) {
		if err := db.Create(&archivedNode).Error; err != nil {
			return fmt.Errorf("Create %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	if err := db.Delete(&node).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// Refresh the last status log for this node
func refreshNodeLastEventByUUID(UUID, event string) error {
	node, err := getNodeByUUID(UUID)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	if err := db.Model(&node).Update(event, time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// Refresh the last status log for this node
func refreshNodeLastEventByKey(nodeKey, event string) error {
	node, err := getNodeByKey(nodeKey)
	if err != nil {
		return err
	}
	if err := db.Model(&node).Update(event, time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// Refresh the last status log for this node
func refreshNodeLastStatus(UUID string) error {
	return refreshNodeLastEventByUUID(UUID, "last_status")
}

// Refresh the last result log for this node
func refreshNodeLastResult(UUID string) error {
	return refreshNodeLastEventByUUID(UUID, "last_result")
}

// Refresh the last configuration for this node
func refreshNodeLastConfig(nodeKey string) error {
	return refreshNodeLastEventByKey(nodeKey, "last_config")
}

// Refresh the last on-demand query read for this node
func refreshNodeLastQueryRead(nodeKey string) error {
	return refreshNodeLastEventByKey(nodeKey, "last_query_read")
}

// Refresh the last on-demand query write for this node
func refreshNodeLastQueryWrite(UUID string) error {
	return refreshNodeLastEventByUUID(UUID, "last_query_write")
}
