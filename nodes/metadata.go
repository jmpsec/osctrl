package nodes

// NodeMetadata to hold metadata for a node
type NodeMetadata struct {
	IPAddress       string
	Username        string
	OsqueryUser     string
	Hostname        string
	Localname       string
	ConfigHash      string
	DaemonHash      string
	OsqueryVersion  string
	Platform        string
	PlatformVersion string
}

// GetMetadata to extract the metadata struct from a node
func (n *NodeManager) GetMetadata(node OsqueryNode) NodeMetadata {
	return NodeMetadata{
		IPAddress:       node.IPAddress,
		Username:        node.Username,
		OsqueryUser:     node.OsqueryUser,
		Hostname:        node.Hostname,
		Localname:       node.Localname,
		ConfigHash:      node.ConfigHash,
		DaemonHash:      node.DaemonHash,
		OsqueryVersion:  node.OsqueryVersion,
		Platform:        node.Platform,
		PlatformVersion: node.PlatformVersion,
	}
}
