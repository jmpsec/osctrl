package types

import (
	"encoding/json"
	"strconv"

	"github.com/jmpsec/osctrl/queries"
)

// Types of log types
const (
	StatusLog string = "status"
	ResultLog string = "result"
	QueryLog  string = "query"
)

// OSVersionTable provided on enrollment, table os_version
type OSVersionTable struct {
	ID           string `json:"_id"`
	Codename     string `json:"codename"`
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	Name         string `json:"name"`
	Patch        string `json:"patch"`
	Platform     string `json:"platform"`
	PlatformLike string `json:"platform_like"`
	Version      string `json:"version"`
}

// OsqueryInfoTable provided on enrollment, table osquery_info
type OsqueryInfoTable struct {
	BuildDistro   string `json:"build_distro"`
	BuildPlatform string `json:"build_platform"`
	ConfigHash    string `json:"config_hash"`
	ConfigValid   string `json:"config_valid"`
	Extension     string `json:"extensions"`
	InstanceID    string `json:"instance_id"`
	PID           string `json:"pid"`
	StartTime     string `json:"start_time"`
	UUID          string `json:"uuid"`
	Version       string `json:"version"`
	Watcher       string `json:"watcher"`
}

// PlatformInfoTable provided on enrollment, table platform_info
type PlatformInfoTable struct {
	Address    string `json:"address"`
	Date       string `json:"date"`
	Extra      string `json:"extra"`
	Revision   string `json:"revision"`
	Size       string `json:"size"`
	Vendor     string `json:"vendor"`
	Version    string `json:"version"`
	VolumeSize string `json:"volume_size"`
}

// SystemInfoTable provided on enrollment, table system_info
type SystemInfoTable struct {
	ComputerName     string `json:"computer_name"`
	CPUBrand         string `json:"cpu_brand"`
	CPULogicalCores  string `json:"cpu_logical_cores"`
	CPUPhysicalCores string `json:"cpu_physical_cores"`
	CPUSubtype       string `json:"cpu_subtype"`
	CPUType          string `json:"cpu_type"`
	HardwareModel    string `json:"hardware_model"`
	HardwareSerial   string `json:"hardware_serial"`
	HardwareVendor   string `json:"hardware_vendor"`
	HardwareVersion  string `json:"hardware_version"`
	Hostname         string `json:"hostname"`
	LocalHostname    string `json:"local_hostname"`
	PhysicalMemory   string `json:"physical_memory"`
	UUID             string `json:"uuid"`
}

// GenericRequest to some endpoints
type GenericRequest struct {
	NodeKey string `json:"node_key"`
}

// GenericResponse for osquery nodes
type GenericResponse struct {
	NodeInvalid bool `json:"node_invalid"`
}

// EnrollRequest received when nodes enroll
type EnrollRequest struct {
	EnrollSecret   string `json:"enroll_secret"`
	HostIdentifier string `json:"host_identifier"`
	PlatformType   string `json:"platform_type"`
	HostDetails    struct {
		EnrollOSVersion    OSVersionTable    `json:"os_version"`
		EnrollOsqueryInfo  OsqueryInfoTable  `json:"osquery_info"`
		EnrollSystemInfo   SystemInfoTable   `json:"system_info"`
		EnrollPlatformInfo PlatformInfoTable `json:"platform_info"`
	} `json:"host_details"`
}

// EnrollResponse to be returned to agents
type EnrollResponse struct {
	NodeKey     string `json:"node_key"`
	NodeInvalid bool   `json:"node_invalid"`
}

// ConfigRequest received when nodes request configuration
type ConfigRequest GenericRequest

// ConfigResponse for configuration requests from nodes
type ConfigResponse GenericResponse

// LogRequest received to process logs
type LogRequest struct {
	NodeKey string          `json:"node_key"`
	LogType string          `json:"log_type"`
	Data    json.RawMessage `json:"data"`
}

// LogResponse for log requests from nodes
type LogResponse GenericResponse

// LogDecorations for decorations field in node logs requests
type LogDecorations struct {
	Username       string `json:"username"`
	OsqueryUser    string `json:"osquery_user"`
	LocalHostname  string `json:"local_hostname"`
	Hostname       string `json:"hostname"`
	OsqueryVersion string `json:"osquery_version"`
	ConfigHash     string `json:"config_hash"`
	DaemonHash     string `json:"osquery_md5"`
}

// StringInt to parse numbers that could be strings
type StringInt int

// UnmarshalJSON implements the json.Unmarshaler interface, which
// allows us to ingest values of any json type as an int and run our custom conversion
func (si *StringInt) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*int)(si))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*si = StringInt(i)
	return nil
}

// LogResultData to be used processing result logs from nodes
type LogResultData struct {
	Name           string          `json:"name"`
	Epoch          int64           `json:"epoch"`
	Action         string          `json:"action"`
	Columns        json.RawMessage `json:"columns"`
	Counter        int             `json:"counter"`
	UnixTime       StringInt       `json:"unixTime"`
	Decorations    LogDecorations  `json:"decorations"`
	CalendarTime   string          `json:"calendarTime"`
	HostIdentifier string          `json:"hostIdentifier"`
}

// LogStatusData to be used processing status logs from nodes
type LogStatusData struct {
	Line           string         `json:"line"`
	Message        string         `json:"message"`
	Version        string         `json:"version"`
	Filename       string         `json:"filename"`
	Severity       string         `json:"severity"`
	UnixTime       StringInt      `json:"unixTime"`
	Decorations    LogDecorations `json:"decorations"`
	CalendarTime   string         `json:"calendarTime"`
	HostIdentifier string         `json:"hostIdentifier"`
}

// LogGenericData to parse both status and result logs
type LogGenericData struct {
	HostIdentifier string         `json:"hostIdentifier"`
	Decorations    LogDecorations `json:"decorations"`
	Version        string         `json:"version"`
}

// QueryReadRequest received to get on-demand queries
type QueryReadRequest GenericRequest

// QueryReadResponse for on-demand queries from nodes
type QueryReadResponse struct {
	Queries     queries.QueryReadQueries `json:"queries"`
	NodeInvalid bool                     `json:"node_invalid"`
}

// AcceleratedQueryReadResponse for accelerated on-demand queries from nodes
// https://github.com/osquery/osquery/blob/master/osquery/distributed/distributed.cpp#L219-L231
type AcceleratedQueryReadResponse struct {
	Queries     queries.QueryReadQueries `json:"queries"`
	NodeInvalid bool                     `json:"node_invalid"`
	Accelerate  int                      `json:"accelerate"`
}

// QueryWriteQueries to hold the on-demand queries results
type QueryWriteQueries map[string]json.RawMessage

// QueryWriteStatuses to hold the on-demand queries statuses
type QueryWriteStatuses map[string]int

// QueryWriteMessages to hold the on-demand queries messages
type QueryWriteMessages map[string]string

// QueryWriteRequest to receive on-demand queries results
type QueryWriteRequest struct {
	Queries  QueryWriteQueries  `json:"queries"`
	Statuses QueryWriteStatuses `json:"statuses"`
	Messages QueryWriteMessages `json:"messages"`
	NodeKey  string             `json:"node_key"`
}

// QueryCarveScheduled to receive confirmation for scheduled carved file
type QueryCarveScheduled struct {
	Time      string `json:"time"`
	SHA256    string `json:"sha256"`
	Size      string `json:"size"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	CarveGUID string `json:"carve_guid"`
	RequestID string `json:"request_id"`
	Carve     string `json:"carve"`
}

// QueryWriteResponse for on-demand queries results from nodes
type QueryWriteResponse GenericResponse

// QueryWriteData to store result of on-demand queries
type QueryWriteData struct {
	Name    string          `json:"name"`
	Result  json.RawMessage `json:"result"`
	Status  int             `json:"status"`
	Message string          `json:"message"`
}

// CarveInitRequest received to begin a carve
type CarveInitRequest struct {
	BlockCount int    `json:"block_count"`
	BlockSize  int    `json:"block_size"`
	CarveSize  int    `json:"carve_size"`
	CarveID    string `json:"carve_id"`
	RequestID  string `json:"request_id"`
	NodeKey    string `json:"node_key"`
}

// CarveInitResponse for osquery nodes
type CarveInitResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id"`
}

// CarveBlockRequest received to begin a carve
type CarveBlockRequest struct {
	BlockID   int    `json:"block_id"`
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id"`
	Data      string `json:"data"`
}

// CarveBlockResponse for osquery nodes
type CarveBlockResponse struct {
	Success bool `json:"success"`
}
