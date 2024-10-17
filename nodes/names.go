package nodes

import (
	"fmt"

	"gorm.io/gorm"
)

// NodeHistoryHostname to keep track of all IP Addresses for nodes
type NodeHistoryHostname struct {
	gorm.Model
	UUID     string `gorm:"index"`
	Hostname string
	Count    int
}

// NodeHistoryLocalname to keep track of all IP Addresses for nodes
type NodeHistoryLocalname struct {
	gorm.Model
	UUID      string `gorm:"index"`
	Localname string
	Count     int
}

// NodeHistoryUsername to keep track of all usernames for nodes
type NodeHistoryUsername struct {
	gorm.Model
	UUID     string `gorm:"index"`
	Username string
	Count    int
}

// NewHistoryHostname to insert new entry for the history of Hostnames
func (n *NodeManager) NewHistoryHostname(entry NodeHistoryHostname) error {
	if err := n.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("Create newNodeHistoryHostname %v", err)
	}
	return nil
}

// NewHistoryLocalname to insert new entry for the history of Localnames
func (n *NodeManager) NewHistoryLocalname(entry NodeHistoryLocalname) error {
	if err := n.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("Create newNodeHistoryLocalname %v", err)
	}
	return nil
}

// NewHistoryUsername to insert new entry for the history of Usernames
func (n *NodeManager) NewHistoryUsername(entry NodeHistoryUsername) error {
	if err := n.DB.Create(&entry).Error; err != nil {
		return fmt.Errorf("Create newNodeHistoryUsername %v", err)
	}
	return nil
}

// SeenUsername to check if an username has been seen per node by UUID
func (n *NodeManager) SeenUsername(uuid, username string) bool {
	var results int64
	n.DB.Model(&NodeHistoryUsername{}).Where("uuid = ? AND username = ?", uuid, username).Count(&results)
	return (results > 0)
}

// SeenHostname to check if an hostname has been seen per node by UUID
func (n *NodeManager) SeenHostname(uuid, hostname string) bool {
	var results int64
	n.DB.Model(&NodeHistoryHostname{}).Where("uuid = ? AND hostname = ?", uuid, hostname).Count(&results)
	return (results > 0)
}

// SeenLocalname to check if an localname has been seen per node by UUID
func (n *NodeManager) SeenLocalname(uuid, localname string) bool {
	var results int64
	n.DB.Model(&NodeHistoryLocalname{}).Where("uuid = ? AND localname = ?", uuid, localname).Count(&results)
	return (results > 0)
}

// RecordLocalname to update and archive the node localname
func (n *NodeManager) RecordLocalname(localname string, node OsqueryNode) error {
	if localname == "" {
		return nil
	}
	if !n.SeenLocalname(node.UUID, localname) {
		e := NodeHistoryLocalname{
			UUID:      node.UUID,
			Localname: localname,
			Count:     1,
		}
		if err := n.NewHistoryLocalname(e); err != nil {
			return fmt.Errorf("newNodeHistoryLocalname %v", err)
		}
	} else {
		if err := n.IncHistoryLocalname(node.UUID, localname); err != nil {
			return fmt.Errorf("newNodeHistoryLocalname %v", err)
		}
	}
	if localname != node.Localname {
		if err := n.DB.Model(&node).Update("localname", localname).Error; err != nil {
			return fmt.Errorf("Update node %v", err)
		}
	}
	return nil
}

// RecordHostname to update and archive the node hostname
func (n *NodeManager) RecordHostname(hostname string, node OsqueryNode) error {
	if hostname == "" {
		return nil
	}
	if !n.SeenLocalname(node.UUID, hostname) {
		e := NodeHistoryHostname{
			UUID:     node.UUID,
			Hostname: hostname,
			Count:    1,
		}
		if err := n.NewHistoryHostname(e); err != nil {
			return fmt.Errorf("newNodeHistoryHostname %v", err)
		}
	} else {
		if err := n.IncHistoryLocalname(node.UUID, hostname); err != nil {
			return fmt.Errorf("newNodeHistoryHostname %v", err)
		}
	}
	if hostname != node.Hostname {
		if err := n.DB.Model(&node).Update("hostname", hostname).Error; err != nil {
			return fmt.Errorf("Update node %v", err)
		}
	}
	return nil
}

// RecordUsername to update and archive the node username
func (n *NodeManager) RecordUsername(username string, node OsqueryNode) error {
	if username == "" {
		return nil
	}
	if !n.SeenUsername(node.UUID, username) {
		e := NodeHistoryUsername{
			UUID:     node.UUID,
			Username: username,
			Count:    1,
		}
		if err := n.NewHistoryUsername(e); err != nil {
			return fmt.Errorf("newNodeHistoryUsername %v", err)
		}
	} else {
		if err := n.IncHistoryUsername(node.UUID, username); err != nil {
			return fmt.Errorf("newNodeHistoryUsername %v", err)
		}
	}
	if username != node.Username {
		if err := n.DB.Model(&node).Update("username", username).Error; err != nil {
			return fmt.Errorf("Update node %v", err)
		}
	}
	return nil
}

// GetHistoryLocalname to retrieve the History localname record by UUID and the localname
func (n *NodeManager) GetHistoryLocalname(uuid, localname string) (NodeHistoryLocalname, error) {
	var nodeLocalname NodeHistoryLocalname
	if err := n.DB.Where("uuid = ? AND localname = ?", uuid, localname).Order("updated_at").First(&nodeLocalname).Error; err != nil {
		return nodeLocalname, err
	}
	return nodeLocalname, nil
}

// GetHistoryHostname to retrieve the History hostname record by UUID and the hostname
func (n *NodeManager) GetHistoryHostname(uuid, hostname string) (NodeHistoryHostname, error) {
	var nodeHostname NodeHistoryHostname
	if err := n.DB.Where("uuid = ? AND hostname = ?", uuid, hostname).Order("updated_at").First(&nodeHostname).Error; err != nil {
		return nodeHostname, err
	}
	return nodeHostname, nil
}

// GetHistoryUsername to retrieve the History username record by UUID and the username
func (n *NodeManager) GetHistoryUsername(uuid, username string) (NodeHistoryUsername, error) {
	var nodeUsername NodeHistoryUsername
	if err := n.DB.Where("uuid = ? AND username = ?", uuid, username).Order("updated_at").First(&nodeUsername).Error; err != nil {
		return nodeUsername, err
	}
	return nodeUsername, nil
}

// IncHistoryLocalname to increase the count for this localname
func (n *NodeManager) IncHistoryLocalname(uuid, localname string) error {
	nodeLocalname, err := n.GetHistoryLocalname(uuid, localname)
	if err != nil {
		return fmt.Errorf("getNodeHistoryLocalname %v", err)
	}
	if err := n.DB.Model(&nodeLocalname).Update("count", nodeLocalname.Count+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// IncHistoryUsername to increase the count for this username
func (n *NodeManager) IncHistoryUsername(uuid, username string) error {
	nodeUsername, err := n.GetHistoryUsername(uuid, username)
	if err != nil {
		return fmt.Errorf("getNodeHistoryUsername %v", err)
	}
	if err := n.DB.Model(&nodeUsername).Update("count", nodeUsername.Count+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// IncHistoryHostname to increase the count for this hostname
func (n *NodeManager) IncHistoryHostname(uuid, localname string) error {
	nodeLocalname, err := n.GetHistoryHostname(uuid, localname)
	if err != nil {
		return fmt.Errorf("getNodeHistoryLocalname %v", err)
	}
	if err := n.DB.Model(&nodeLocalname).Update("count", nodeLocalname.Count+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}
