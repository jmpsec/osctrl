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
	BytesReceived   int
}
