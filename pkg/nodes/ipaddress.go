package nodes

import (
	"fmt"

	"gorm.io/gorm"
)

// NodeHistoryIPAddress to keep track of all IP Addresses for nodes
type NodeHistoryIPAddress struct {
	gorm.Model
	UUID      string `gorm:"index"`
	IPAddress string
	Count     int
}

// UpdateIPAddress to update the node IP Address
func (n *NodeManager) UpdateIPAddress(ipaddress string, node OsqueryNode) error {
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
		if err := n.NewHistoryIPAddress(e); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
		if err := n.DB.Model(&node).Updates(data).Error; err != nil {
			return fmt.Errorf("Updates %v", err)
		}
	} else {
		if err := n.IncHistoryIPAddress(node.UUID, ipaddress); err != nil {
			return fmt.Errorf("incNodeHistoryIPAddress %v", err)
		}
	}
	return nil
}

// RecordIPAddress to update and archive the node IP Address
func (n *NodeManager) RecordIPAddress(ipaddress string, node OsqueryNode) error {
	if ipaddress == "" {
		return nil
	}
	if !n.SeenIPAddress(node.UUID, ipaddress) {
		e := NodeHistoryIPAddress{
			UUID:      node.UUID,
			IPAddress: ipaddress,
			Count:     1,
		}
		if err := n.NewHistoryIPAddress(e); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
	} else {
		if err := n.IncHistoryIPAddress(node.UUID, ipaddress); err != nil {
			return fmt.Errorf("newNodeHistoryIPAddress %v", err)
		}
	}
	return nil
}

// UpdateIPAddressByUUID to update node IP Address by UUID
func (n *NodeManager) UpdateIPAddressByUUID(ipaddress, uuid string) error {
	node, err := n.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("getNodeByUUID %v", err)
	}
	return n.UpdateIPAddress(ipaddress, node)
}

// UpdateIPAddressByKey to update node IP Address by node_key
func (n *NodeManager) UpdateIPAddressByKey(ipaddress, nodekey string) error {
	node, err := n.GetByKey(nodekey)
	if err != nil {
		return fmt.Errorf("getNodeByKey %v", err)
	}
	return n.UpdateIPAddress(ipaddress, node)
}

// NewHistoryIPAddress to insert new entry for the history of IP Addresses
func (n *NodeManager) NewHistoryIPAddress(entry NodeHistoryIPAddress) error {
	if err := n.DB.Create(&entry).Error; err != nil {
		return err
	}
	return nil
}

// GetHistoryIPAddress to retrieve the History IP Address record by UUID and the IP Address
func (n *NodeManager) GetHistoryIPAddress(uuid, ipaddress string) (NodeHistoryIPAddress, error) {
	var nodeip NodeHistoryIPAddress
	if err := n.DB.Where("uuid = ? AND ip_address = ?", uuid, ipaddress).Order("updated_at").First(&nodeip).Error; err != nil {
		return nodeip, err
	}
	return nodeip, nil
}

// IncHistoryIPAddress to increase the count for this IP Address
func (n *NodeManager) IncHistoryIPAddress(uuid, ipaddress string) error {
	nodeip, err := n.GetHistoryIPAddress(uuid, ipaddress)
	if err != nil {
		return fmt.Errorf("getNodeHistoryIPAddress %v", err)
	}
	if err := n.DB.Model(&nodeip).Update("count", nodeip.Count+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// SeenIPAddress to check if an IP Address has been seen per node by UUID
func (n *NodeManager) SeenIPAddress(uuid, ipaddress string) bool {
	var results int64
	n.DB.Model(&NodeHistoryIPAddress{}).Where("uuid = ? AND ip_address = ?", uuid, ipaddress).Count(&results)
	return (results > 0)
}
