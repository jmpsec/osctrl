package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/google/uuid"
	internalconfig "github.com/jmpsec/osctrl/tools/fake_news_go/internal/config"
	internaldiscovery "github.com/jmpsec/osctrl/tools/fake_news_go/internal/discovery"
	internalmetrics "github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
	internalmodel "github.com/jmpsec/osctrl/tools/fake_news_go/internal/model"
	internalosquery "github.com/jmpsec/osctrl/tools/fake_news_go/internal/osquery"
	internalreport "github.com/jmpsec/osctrl/tools/fake_news_go/internal/report"
	internalrunner "github.com/jmpsec/osctrl/tools/fake_news_go/internal/runner"
	internaltransport "github.com/jmpsec/osctrl/tools/fake_news_go/internal/transport"
	internaltui "github.com/jmpsec/osctrl/tools/fake_news_go/internal/tui"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	TLS_URL = "http://localhost:9000/"

	TLS_ENROLL      = "/enroll"
	TLS_LOG         = "/log"
	TLS_CONFIG      = "/config"
	TLS_QUERY_READ  = "/read"
	TLS_QUERY_WRITE = "/write"

	LOG_INTERVAL        = 60
	CONFIG_INTERVAL     = 45
	QUERY_READ_INTERVAL = 30

	STATE_JSON = "fake_news_state.json"
	OSQUERYI   = "osqueryi"
)

// OutputMode defines the output verbosity level
type OutputMode int

const (
	QuietMode OutputMode = iota
	SummaryMode
	VerboseMode
	DashboardMode
	JSONMode
)

// OperationType represents different types of operations
type OperationType int

const (
	EnrollOp OperationType = iota
	StatusOp
	ResultOp
	ConfigOp
	QueryReadOp
	QueryWriteOp
)

// LatencyStats tracks latency statistics for an operation type
type LatencyStats struct {
	mu           sync.RWMutex
	latencies    []time.Duration
	min          time.Duration
	max          time.Duration
	total        time.Duration
	count        int64
	successCount int64
	failCount    int64
}

// OperationStats tracks statistics for all operation types
type OperationStats struct {
	enroll     LatencyStats
	status     LatencyStats
	result     LatencyStats
	config     LatencyStats
	queryRead  LatencyStats
	queryWrite LatencyStats
}

// URLStats tracks statistics per URL endpoint
type URLStats struct {
	mu    sync.RWMutex
	stats map[string]*LatencyStats
}

// GlobalStats holds global statistics
type GlobalStats struct {
	mu          sync.RWMutex
	operations  OperationStats
	urls        URLStats
	startTime   time.Time
	totalNodes  int
	activeNodes int
	lastUpdate  time.Time
}

var (
	platforms = []string{
		"ubuntu14", "ubuntu16", "ubuntu18",
		"centos6", "centos7",
		"debian8", "debian9",
		"freebsd", "darwin", "windows",
	}

	osqueryVersions = []string{
		"5.0.1", "4.9.0", "3.3.1", "3.3.2",
		"5.1.0", "5.3.0", "4.8.2", "5.23.1",
	}

	// Global statistics instance
	globalStats = &GlobalStats{
		startTime: time.Now(),
		urls: URLStats{
			stats: make(map[string]*LatencyStats),
		},
	}

	osqueryRunner OSQueryRunner = internalosquery.NewDefault(OSQUERYI)
)

type Node = internalmodel.Node

// SystemInfo represents system information for enrollment
type SystemInfo struct {
	ComputerName     string `json:"computer_name"`
	CPUBrand         string `json:"cpu_brand"`
	CPULogicalCores  string `json:"cpu_logical_cores"`
	CPUPhysicalCores string `json:"cpu_physical_cores"`
	CPUSubtype       string `json:"cpu_subtype"`
	CPUType          string `json:"cpu_type"`
	HardwareModel    string `json:"hardware_model"`
	Hostname         string `json:"hostname"`
	LocalHostname    string `json:"local_hostname"`
	PhysicalMemory   string `json:"physical_memory"`
	UUID             string `json:"uuid"`
}

// OSQueryInfo represents osquery information
type OSQueryInfo struct {
	BuildDistro   string `json:"build_distro"`
	BuildPlatform string `json:"build_platform"`
	ConfigHash    string `json:"config_hash"`
	ConfigValid   string `json:"config_valid"`
	Extensions    string `json:"extensions"`
	InstanceID    string `json:"instance_id"`
	PID           string `json:"pid"`
	StartTime     string `json:"start_time"`
	UUID          string `json:"uuid"`
	Version       string `json:"version"`
	Watcher       string `json:"watcher"`
}

// OSVersion represents OS version information
type OSVersion struct {
	ID           string `json:"_id,omitempty"`
	Codename     string `json:"codename,omitempty"`
	Build        string `json:"build,omitempty"`
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	Name         string `json:"name"`
	Patch        string `json:"patch"`
	Platform     string `json:"platform"`
	PlatformLike string `json:"platform_like,omitempty"`
	Version      string `json:"version"`
	InstallDate  string `json:"install_date,omitempty"`
}

// HostDetails represents host details for enrollment
type HostDetails struct {
	OSVersion   OSVersion   `json:"os_version"`
	OSQueryInfo OSQueryInfo `json:"osquery_info"`
	SystemInfo  SystemInfo  `json:"system_info"`
}

// EnrollRequest represents enrollment request
type EnrollRequest struct {
	EnrollSecret   string      `json:"enroll_secret"`
	HostIdentifier string      `json:"host_identifier"`
	PlatformType   string      `json:"platform_type"`
	HostDetails    HostDetails `json:"host_details"`
}

// EnrollResponse represents enrollment response
type EnrollResponse struct {
	NodeKey string `json:"node_key"`
}

// LogRequest represents log request
type LogRequest struct {
	NodeKey string      `json:"node_key"`
	LogType string      `json:"log_type"`
	Data    interface{} `json:"data"`
}

// ConfigRequest represents config request
type ConfigRequest struct {
	NodeKey string `json:"node_key"`
}

// QueryReadRequest represents query read request
type QueryReadRequest struct {
	NodeKey string `json:"node_key"`
}

// QueryWriteRequest represents query write request
type QueryWriteRequest struct {
	NodeKey  string                 `json:"node_key"`
	Queries  map[string]interface{} `json:"queries"`
	Statuses map[string]int         `json:"statuses"`
	Messages map[string]string      `json:"messages"`
}

// StatusLog represents a status log entry
type StatusLog struct {
	HostIdentifier string `json:"hostIdentifier"`
	CalendarTime   string `json:"calendarTime"`
	UnixTime       string `json:"unixTime"`
	Severity       string `json:"severity"`
	Filename       string `json:"filename"`
	Line           string `json:"line"`
	Message        string `json:"message"`
	Version        string `json:"version"`
}

// ResultLog represents a result log entry
type ResultLog struct {
	Name           string            `json:"name"`
	HostIdentifier string            `json:"hostIdentifier"`
	CalendarTime   string            `json:"calendarTime"`
	UnixTime       string            `json:"unixTime"`
	Epoch          int               `json:"epoch"`
	Counter        int               `json:"counter"`
	Numerics       bool              `json:"numerics"`
	Decorations    map[string]string `json:"decorations"`
	Columns        map[string]string `json:"columns"`
	Action         string            `json:"action"`
}

// FakeNewsConfig holds configuration for the fake news generator
type FakeNewsConfig struct {
	URL             string
	Env             string
	Secret          string
	Nodes           int
	StatusInterval  int
	ResultInterval  int
	ConfigInterval  int
	QueryInterval   int
	Verbose         bool
	Insecure        bool
	OutputMode      OutputMode
	SummaryInterval int
	StateFile       string
}

type runtimeTarget struct {
	EnvUUID   string
	Secret    string
	URL       string
	StateFile string
}

// HTTPClient wraps http.Client with custom configuration
type HTTPClient struct {
	client *internaltransport.Client
	debug  bool
}

type OSQueryRunner interface {
	RunJSON(query string) ([]map[string]interface{}, error)
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(debug bool, insecure bool) *HTTPClient {
	return &HTTPClient{
		client: internaltransport.NewDefault(insecure),
		debug:  debug,
	}
}

// Post sends a POST request and returns status code and parsed response
func (c *HTTPClient) Post(url string, data interface{}, headers map[string]string) (int, map[string]interface{}, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}

	if c.debug {
		fmt.Printf("POST to %s\n", url)
		fmt.Printf("DATA: %s\n", string(jsonData))
	}

	resp, err := c.client.PostJSON(context.Background(), url, data, headers)
	if err != nil {
		return 0, nil, err
	}
	body := resp.RawBody

	if c.debug {
		fmt.Printf("HTTP %d\n", resp.StatusCode)
	}

	result := resp.Body
	if resp.StatusCode == 200 {
		if c.debug {
			prettyJSON, _ := json.MarshalIndent(result, "", "  ")
			fmt.Printf("%s\n", string(prettyJSON))
		}
	} else {
		// Print error and output when not 200
		fmt.Printf("HTTP request to %s returned status %d\n", url, resp.StatusCode)
		fmt.Printf("Response body: %s\n", string(body))
		// Write error to external file
		f, ferr := os.OpenFile("http_errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if ferr == nil {
			logLine := fmt.Sprintf("%s | %s | HTTP %d\n%s\n\n", time.Now().Format(time.RFC3339), url, resp.StatusCode, string(body))
			_, _ = f.WriteString(logLine)
			f.Close()
		}
	}

	return resp.StatusCode, result, nil
}

// generateRandomIP generates a random IP address
func generateRandomIP(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		r.Intn(256),
		r.Intn(256),
		r.Intn(256),
		r.Intn(256))
}

// generateHostname generates a hostname based on platform
func generateHostname(platform string, r *rand.Rand) string {
	suffixes := []string{"Prod", "Legacy", "Test", "Dev", "PC"}
	suffix := suffixes[r.Intn(len(suffixes))]
	titleCaser := cases.Title(language.English)
	return fmt.Sprintf("%s-%s", titleCaser.String(platform), suffix)
}

// generateRandomNode generates a random node
func generateRandomNode(r *rand.Rand) Node {
	platform := platforms[r.Intn(len(platforms))]
	return Node{
		Target:     platform,
		IP:         generateRandomIP(r),
		Name:       generateHostname(platform, r),
		Version:    osqueryVersions[r.Intn(len(osqueryVersions))],
		Identifier: uuid.New().String(),
		Key:        "",
	}
}

// generateRandomNodes generates n random nodes
func generateRandomNodes(n int, r *rand.Rand) []Node {
	nodes := make([]Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = generateRandomNode(r)
	}
	return nodes
}

// generateSystemInfo generates system info for a node
func generateSystemInfo(name, uuid string) SystemInfo {
	return SystemInfo{
		ComputerName:     name,
		CPUBrand:         "Intel(R) Core(TM) i7-7920HQ CPU @ 3.10GHz",
		CPULogicalCores:  "4",
		CPUPhysicalCores: "4",
		CPUSubtype:       "158",
		CPUType:          "x86_64",
		HardwareModel:    "",
		Hostname:         name,
		LocalHostname:    name,
		PhysicalMemory:   "2095869952",
		UUID:             uuid,
	}
}

// generateOSQueryInfo generates osquery info for a node
func generateOSQueryInfo(uuidStr, version string) OSQueryInfo {
	return OSQueryInfo{
		BuildDistro:   "build_distro",
		BuildPlatform: "build_platform",
		ConfigHash:    "",
		ConfigValid:   "0",
		Extensions:    "active",
		InstanceID:    uuid.New().String(),
		PID:           "11",
		StartTime:     "1564800635",
		UUID:          uuidStr,
		Version:       version,
		Watcher:       "9",
	}
}

// getOSVersion returns OS version info based on platform
func getOSVersion(platform string) OSVersion {
	switch platform {
	case "ubuntu14":
		return OSVersion{
			ID:           "14.04",
			Major:        "14",
			Minor:        "04",
			Name:         "Ubuntu",
			Patch:        "0",
			Platform:     "ubuntu",
			PlatformLike: "debian",
			Version:      "14.04.5 LTS, Trusty Tahr",
		}
	case "ubuntu16":
		return OSVersion{
			ID:           "16.04",
			Codename:     "xenial",
			Major:        "16",
			Minor:        "04",
			Name:         "Ubuntu",
			Patch:        "0",
			Platform:     "ubuntu",
			PlatformLike: "debian",
			Version:      "16.04.6 LTS (Xenial Xerus)",
		}
	case "ubuntu18":
		return OSVersion{
			ID:           "18.04",
			Codename:     "bionic",
			Major:        "18",
			Minor:        "04",
			Name:         "Ubuntu",
			Patch:        "0",
			Platform:     "ubuntu",
			PlatformLike: "debian",
			Version:      "18.04.2 LTS (Bionic Beaver)",
		}
	case "centos6":
		return OSVersion{
			Build:        "",
			Major:        "6",
			Minor:        "10",
			Name:         "CentOS",
			Patch:        "0",
			Platform:     "rhel",
			PlatformLike: "rhel",
			Version:      "CentOS release 6.10 (Final)",
		}
	case "centos7":
		return OSVersion{
			ID:           "7",
			Build:        "",
			Major:        "7",
			Minor:        "6",
			Name:         "CentOS Linux",
			Patch:        "1810",
			Platform:     "rhel",
			PlatformLike: "rhel",
			Version:      "CentOS Linux release 7.6.1810 (Core)",
		}
	case "debian8":
		return OSVersion{
			ID:       "8",
			Major:    "8",
			Minor:    "0",
			Name:     "Debian GNU/Linux",
			Patch:    "0",
			Platform: "debian",
			Version:  "8 (jessie)",
		}
	case "debian9":
		return OSVersion{
			ID:       "9",
			Major:    "9",
			Minor:    "0",
			Name:     "Debian GNU/Linux",
			Patch:    "0",
			Platform: "debian",
			Version:  "9 (stretch)",
		}
	case "freebsd":
		return OSVersion{
			Build:    "STABLE",
			Major:    "11",
			Minor:    "3",
			Name:     "FreeBSD",
			Patch:    "",
			Platform: "freebsd",
			Version:  "11.3-STABLE",
		}
	case "darwin":
		return OSVersion{
			Build:        "16A323",
			Major:        "10",
			Minor:        "14",
			Name:         "Mac OS X",
			Patch:        "0",
			Platform:     "darwin",
			PlatformLike: "darwin",
			Version:      "10.14",
		}
	case "windows":
		return OSVersion{
			Build:        "17763",
			Codename:     "Windows 10 Pro",
			InstallDate:  "20190119193615.000000-420",
			Major:        "10",
			Minor:        "0",
			Name:         "Microsoft Windows 10 Pro",
			Platform:     "windows",
			PlatformLike: "windows",
			Version:      "10.0.17763",
		}
	default:
		return getOSVersion("ubuntu18") // fallback
	}
}

// getPlatformType returns platform type number
func getPlatformType(platform string) string {
	switch platform {
	case "ubuntu14", "ubuntu16", "ubuntu18", "centos6", "centos7", "debian8", "debian9":
		return "9"
	case "freebsd":
		return "37"
	case "darwin":
		return "21"
	case "windows":
		return "2"
	default:
		return "9"
	}
}

// generateEnrollRequest generates enrollment request for a node
func generateEnrollRequest(node Node, secret string) EnrollRequest {
	return EnrollRequest{
		EnrollSecret:   secret,
		HostIdentifier: node.Identifier,
		PlatformType:   getPlatformType(node.Target),
		HostDetails: HostDetails{
			OSVersion:   getOSVersion(node.Target),
			OSQueryInfo: generateOSQueryInfo(node.Identifier, node.Version),
			SystemInfo:  generateSystemInfo(node.Name, node.Identifier),
		},
	}
}

// generateConfigRequest generates config request
func generateConfigRequest(nodeKey string) ConfigRequest {
	return ConfigRequest{NodeKey: nodeKey}
}

// generateQueryReadRequest generates query read request
func generateQueryReadRequest(nodeKey string) QueryReadRequest {
	return QueryReadRequest{NodeKey: nodeKey}
}

// generateLogStatus generates status log
func generateLogStatus(node Node) LogRequest {
	status := StatusLog{
		HostIdentifier: node.Identifier,
		CalendarTime:   time.Now().Format(time.RFC1123),
		UnixTime:       strconv.FormatInt(time.Now().Unix(), 10),
		Severity:       "0",
		Filename:       "fake_news.go",
		Line:           "255",
		Message:        "Sent fake log message to TLS",
		Version:        node.Version,
	}
	return LogRequest{
		NodeKey: node.Key,
		LogType: "status",
		Data:    []StatusLog{status},
	}
}

// generateLogResult generates result log
func generateLogResult(node Node) LogRequest {
	result := ResultLog{
		Name:           "uptime",
		HostIdentifier: node.Identifier,
		CalendarTime:   time.Now().Format(time.RFC1123),
		UnixTime:       strconv.FormatInt(time.Now().Unix(), 10),
		Epoch:          0,
		Counter:        0,
		Numerics:       false,
		Decorations: map[string]string{
			"config_hash":     "7155bb2b98162fa5641d340e03a38d0502df34f0",
			"hostname":        node.Name,
			"local_hostname":  node.Name,
			"osquery_md5":     "8e2490cb34e32cb33d6326ca30763167",
			"osquery_user":    "root",
			"osquery_version": node.Version,
			"username":        "user (console)",
		},
		Columns: map[string]string{
			"days":          "0",
			"hours":         "1",
			"minutes":       "2",
			"seconds":       "3",
			"total_seconds": "123456",
		},
		Action: "added",
	}
	return LogRequest{
		NodeKey: node.Key,
		LogType: "result",
		Data:    []ResultLog{result},
	}
}

// executeOSQuery executes an osquery command
func executeOSQuery(query string) ([]map[string]interface{}, error) {
	return osqueryRunner.RunJSON(query)
}

// generateQueryWriteRequest generates query write request
func generateQueryWriteRequest(node Node, queryName string, result []map[string]interface{}) QueryWriteRequest {
	queries := make(map[string]interface{})
	queries[queryName] = result

	statuses := make(map[string]int)
	statuses[queryName] = 0

	messages := make(map[string]string)
	messages[queryName] = ""

	return QueryWriteRequest{
		NodeKey:  node.Key,
		Queries:  queries,
		Statuses: statuses,
		Messages: messages,
	}
}

// enrollNode enrolls a node and returns the node key
func enrollNode(client *HTTPClient, node Node, secret string, enrollURL string, config FakeNewsConfig) string {
	start := time.Now()
	headers := map[string]string{"X-Real-IP": node.IP}
	data := generateEnrollRequest(node, secret)

	code, resp, err := client.Post(enrollURL, data, headers)
	requestTime := time.Since(start)

	success := err == nil && code == 200
	logOperationWithURL(EnrollOp, node.Name, enrollURL, requestTime, success, config)

	if err != nil {
		if config.OutputMode == VerboseMode {
			fmt.Printf("HTTP request failed: %v\n", err)
		}
		return node.Key
	}

	if code != 200 {
		if config.OutputMode == VerboseMode {
			fmt.Printf("HTTP %d with %s\n", code, enrollURL)
		}
		return node.Key
	}

	if nodeKey, ok := resp["node_key"].(string); ok {
		return nodeKey
	}

	return node.Key
}

// logStatus sends status logs for a node
func logStatus(ctx context.Context, client *HTTPClient, node *Node, urls map[string]string, secret string, interval time.Duration, mutex *sync.Mutex, config FakeNewsConfig) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			headers := map[string]string{"X-Real-IP": node.IP}
			data := generateLogStatus(*node)

			code, resp, err := client.Post(urls["log"], data, headers)
			requestTime := time.Since(start)

			success := err == nil && code == 200
			logOperationWithURL(StatusOp, node.Name, urls["log"], requestTime, success, config)

			if err != nil {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP request failed: %v\n", err)
				}
				continue
			}

			if code != 200 {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP %d with %s\n", code, urls["log"])
				}
				continue
			}

			if nodeInvalid, ok := resp["node_invalid"].(bool); ok && nodeInvalid {
				mutex.Lock()
				node.Key = enrollNode(client, *node, secret, urls["enroll"], config)
				mutex.Unlock()
			}
		}
	}
}

// logResult sends result logs for a node
func logResult(ctx context.Context, client *HTTPClient, node *Node, urls map[string]string, secret string, interval time.Duration, mutex *sync.Mutex, config FakeNewsConfig) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			headers := map[string]string{"X-Real-IP": node.IP}
			data := generateLogResult(*node)

			code, resp, err := client.Post(urls["log"], data, headers)
			requestTime := time.Since(start)

			success := err == nil && code == 200
			logOperationWithURL(ResultOp, node.Name, urls["log"], requestTime, success, config)

			if err != nil {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP request failed: %v\n", err)
				}
				continue
			}

			if code != 200 {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP %d with %s\n", code, urls["log"])
				}
				continue
			}

			if nodeInvalid, ok := resp["node_invalid"].(bool); ok && nodeInvalid {
				mutex.Lock()
				node.Key = enrollNode(client, *node, secret, urls["enroll"], config)
				mutex.Unlock()
			}
		}
	}
}

// configRequest sends config requests for a node
func configRequest(ctx context.Context, client *HTTPClient, node *Node, urls map[string]string, secret string, interval time.Duration, mutex *sync.Mutex, config FakeNewsConfig) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			headers := map[string]string{"X-Real-IP": node.IP}
			data := generateConfigRequest(node.Key)

			code, resp, err := client.Post(urls["config"], data, headers)
			requestTime := time.Since(start)

			success := err == nil && code == 200
			logOperationWithURL(ConfigOp, node.Name, urls["config"], requestTime, success, config)

			if err != nil {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP request failed: %v\n", err)
				}
				continue
			}

			if code != 200 {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP %d with %s\n", code, urls["config"])
				}
				continue
			}

			if nodeInvalid, ok := resp["node_invalid"].(bool); ok && nodeInvalid {
				mutex.Lock()
				node.Key = enrollNode(client, *node, secret, urls["enroll"], config)
				mutex.Unlock()
			}
		}
	}
}

// queryRead sends query read requests for a node
func queryRead(ctx context.Context, client *HTTPClient, node *Node, urls map[string]string, secret string, interval time.Duration, mutex *sync.Mutex, config FakeNewsConfig) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			headers := map[string]string{"X-Real-IP": node.IP}
			data := generateQueryReadRequest(node.Key)

			code, resp, err := client.Post(urls["query"], data, headers)
			requestTime := time.Since(start)

			success := err == nil && code == 200
			logOperationWithURL(QueryReadOp, node.Name, urls["query"], requestTime, success, config)

			if err != nil {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP request failed: %v\n", err)
				}
				continue
			}

			if code != 200 {
				if config.OutputMode == VerboseMode {
					fmt.Printf("HTTP %d with %s\n", code, urls["query"])
				}
				continue
			}

			if nodeInvalid, ok := resp["node_invalid"].(bool); ok && nodeInvalid {
				mutex.Lock()
				node.Key = enrollNode(client, *node, secret, urls["enroll"], config)
				mutex.Unlock()
			}

			if queries, ok := resp["queries"].(map[string]interface{}); ok && len(queries) > 0 {
				for queryName, query := range queries {
					go queryWrite(client, node, queryName, query, urls["write"], config)
				}
			}
		}
	}
}

// queryWrite sends query write requests
func queryWrite(client *HTTPClient, node *Node, queryName string, query interface{}, writeURL string, config FakeNewsConfig) {
	start := time.Now()
	headers := map[string]string{"X-Real-IP": node.IP}

	// Execute osquery command
	queryStr, ok := query.(string)
	if !ok {
		if config.OutputMode == VerboseMode {
			fmt.Printf("Invalid query format for %s\n", queryName)
		}
		return
	}

	result, err := executeOSQuery(queryStr)
	if err != nil {
		if config.OutputMode == VerboseMode {
			fmt.Printf("Failed to execute osquery: %v\n", err)
		}
		return
	}

	data := generateQueryWriteRequest(*node, queryName, result)
	code, resp, err := client.Post(writeURL, data, headers)
	requestTime := time.Since(start)

	success := err == nil && code == 200
	logOperationWithURL(QueryWriteOp, node.Name, writeURL, requestTime, success, config)

	if err != nil {
		if config.OutputMode == VerboseMode {
			fmt.Printf("HTTP request failed: %v\n", err)
		}
		return
	}

	if code != 200 {
		if config.OutputMode == VerboseMode {
			fmt.Printf("HTTP %d with %s\n", code, writeURL)
		}
		return
	}

	if config.OutputMode == VerboseMode && client.debug {
		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Printf("%s\n", string(prettyJSON))
	}
}

// loadNodesFromFile loads nodes from a JSON file
func loadNodesFromFile(filename string) ([]Node, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var nodes []Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}

	return nodes, nil
}

// saveNodesToFile saves nodes to a JSON file
func saveNodesToFile(nodes []Node, filename string) error {
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// AddLatency adds a latency measurement to the statistics
func (ls *LatencyStats) AddLatency(latency time.Duration, success bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	ls.latencies = append(ls.latencies, latency)
	ls.count++

	if success {
		ls.successCount++
	} else {
		ls.failCount++
	}

	ls.total += latency

	if ls.count == 1 {
		ls.min = latency
		ls.max = latency
	} else {
		if latency < ls.min {
			ls.min = latency
		}
		if latency > ls.max {
			ls.max = latency
		}
	}

	// Keep only last 1000 measurements for percentile calculations
	if len(ls.latencies) > 1000 {
		ls.latencies = ls.latencies[len(ls.latencies)-1000:]
	}
}

// GetStats returns current statistics
func (ls *LatencyStats) GetStats() (min, max, avg time.Duration, p95, p99 time.Duration, count, successCount, failCount int64) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	if ls.count == 0 {
		return 0, 0, 0, 0, 0, 0, 0, 0
	}

	min = ls.min
	max = ls.max
	avg = ls.total / time.Duration(ls.count)
	count = ls.count
	successCount = ls.successCount
	failCount = ls.failCount

	// Calculate percentiles
	if len(ls.latencies) > 0 {
		sorted := make([]time.Duration, len(ls.latencies))
		copy(sorted, ls.latencies)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i] < sorted[j]
		})

		p95Idx := int(float64(len(sorted)) * 0.95)
		p99Idx := int(float64(len(sorted)) * 0.99)

		if p95Idx < len(sorted) {
			p95 = sorted[p95Idx]
		}
		if p99Idx < len(sorted) {
			p99 = sorted[p99Idx]
		}
	}

	return
}

// GetOperationStats returns statistics for a specific operation type
func (gs *GlobalStats) GetOperationStats(opType OperationType) *LatencyStats {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	switch opType {
	case EnrollOp:
		return &gs.operations.enroll
	case StatusOp:
		return &gs.operations.status
	case ResultOp:
		return &gs.operations.result
	case ConfigOp:
		return &gs.operations.config
	case QueryReadOp:
		return &gs.operations.queryRead
	case QueryWriteOp:
		return &gs.operations.queryWrite
	default:
		return nil
	}
}

// RecordOperation records an operation with its latency and success status
func (gs *GlobalStats) RecordOperation(opType OperationType, latency time.Duration, success bool) {
	stats := gs.GetOperationStats(opType)
	if stats != nil {
		stats.AddLatency(latency, success)
	}

	gs.mu.Lock()
	gs.lastUpdate = time.Now()
	gs.mu.Unlock()
}

// RecordURLOperation records an operation for a specific URL
func (gs *GlobalStats) RecordURLOperation(url string, latency time.Duration, success bool) {
	gs.mu.Lock()
	gs.urls.mu.Lock()

	if gs.urls.stats[url] == nil {
		gs.urls.stats[url] = &LatencyStats{}
	}
	gs.urls.stats[url].AddLatency(latency, success)
	gs.lastUpdate = time.Now()

	gs.urls.mu.Unlock()
	gs.mu.Unlock()
}

// GetURLStats returns statistics for all URLs
func (gs *GlobalStats) GetURLStats() map[string]*LatencyStats {
	gs.urls.mu.RLock()
	defer gs.urls.mu.RUnlock()

	result := make(map[string]*LatencyStats)
	for url, stats := range gs.urls.stats {
		result[url] = stats
	}
	return result
}

// GetUptime returns the uptime since start
func (gs *GlobalStats) GetUptime() time.Duration {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return time.Since(gs.startTime)
}

// SetNodeCounts sets the total and active node counts
func (gs *GlobalStats) SetNodeCounts(total, active int) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.totalNodes = total
	gs.activeNodes = active
}

func (gs *GlobalStats) GetNodeCounts() (int, int) {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return gs.totalNodes, gs.activeNodes
}

// printSummary prints a summary of statistics
func printSummary() {
	uptime := globalStats.GetUptime()

	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("FAKE NEWS GENERATOR - PERFORMANCE SUMMARY\n")
	fmt.Printf("Uptime: %s\n", uptime.Round(time.Second))
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	operations := []struct {
		name string
		op   OperationType
	}{
		{"Enroll", EnrollOp},
		{"Status", StatusOp},
		{"Result", ResultOp},
		{"Config", ConfigOp},
		{"Query Read", QueryReadOp},
		{"Query Write", QueryWriteOp},
	}

	for _, op := range operations {
		stats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, _ := stats.GetStats()

		if count > 0 {
			successRate := float64(success) / float64(count) * 100
			fmt.Printf("%-12s | Count: %6d | Success: %5.1f%% | Min: %4dms | Avg: %4dms | Max: %4dms | P95: %4dms | P99: %4dms\n",
				op.name, count, successRate, min.Milliseconds(), avg.Milliseconds(), max.Milliseconds(), p95.Milliseconds(), p99.Milliseconds())
		}
	}

	// Print URL statistics
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Printf("URL STATISTICS - ABSOLUTE NUMBERS\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	urlStats := globalStats.GetURLStats()
	if len(urlStats) > 0 {
		fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "URL", "Total", "Success", "Failed", "Success%")
		fmt.Printf("%s\n", strings.Repeat("-", 80))

		for url, stats := range urlStats {
			_, _, _, _, _, count, success, fail := stats.GetStats()
			if count > 0 {
				successRate := float64(success) / float64(count) * 100
				fmt.Printf("%-50s | %8d | %8d | %8d | %7.1f%%\n",
					url, count, success, fail, successRate)
			}
		}
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 80))
}

// printDashboard prints a real-time dashboard
func printDashboard() {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	uptime := globalStats.GetUptime()

	fmt.Printf("FAKE NEWS GENERATOR - REAL-TIME DASHBOARD\n")
	fmt.Printf("Uptime: %s | Last Update: %s\n", uptime.Round(time.Second), time.Now().Format("15:04:05"))
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	operations := []struct {
		name string
		op   OperationType
	}{
		{"Enroll", EnrollOp},
		{"Status", StatusOp},
		{"Result", ResultOp},
		{"Config", ConfigOp},
		{"Query Read", QueryReadOp},
		{"Query Write", QueryWriteOp},
	}

	fmt.Printf("%-12s | %8s | %8s | %8s | %8s | %8s | %8s | %8s\n",
		"Operation", "Count", "Success%", "Min(ms)", "Avg(ms)", "Max(ms)", "P95(ms)", "P99(ms)")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	for _, op := range operations {
		stats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, _ := stats.GetStats()

		if count > 0 {
			successRate := float64(success) / float64(count) * 100
			fmt.Printf("%-12s | %8d | %7.1f%% | %8d | %8d | %8d | %8d | %8d\n",
				op.name, count, successRate, min.Milliseconds(), avg.Milliseconds(), max.Milliseconds(), p95.Milliseconds(), p99.Milliseconds())
		} else {
			fmt.Printf("%-12s | %8d | %7s | %8s | %8s | %8s | %8s | %8s\n",
				op.name, 0, "-", "-", "-", "-", "-", "-")
		}
	}
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	// Print URL statistics section
	fmt.Printf("\nURL STATISTICS - ABSOLUTE NUMBERS\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "URL", "Total", "Success", "Failed", "Success%")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	urlStats := globalStats.GetURLStats()
	if len(urlStats) > 0 {
		for url, stats := range urlStats {
			_, _, _, _, _, count, success, fail := stats.GetStats()
			if count > 0 {
				successRate := float64(success) / float64(count) * 100
				fmt.Printf("%-50s | %8d | %8d | %8d | %7.1f%%\n",
					url, count, success, fail, successRate)
			}
		}
	} else {
		fmt.Printf("%-50s | %8s | %8s | %8s | %8s\n", "No data yet", "-", "-", "-", "-")
	}
	fmt.Printf("%s\n", strings.Repeat("-", 100))
}

// printJSONStats prints statistics in JSON format
func printJSONStats() {
	stats := make(map[string]interface{})
	stats["uptime_seconds"] = globalStats.GetUptime().Seconds()
	stats["timestamp"] = time.Now().Unix()

	operations := make(map[string]interface{})
	opTypes := []struct {
		name string
		op   OperationType
	}{
		{"enroll", EnrollOp},
		{"status", StatusOp},
		{"result", ResultOp},
		{"config", ConfigOp},
		{"query_read", QueryReadOp},
		{"query_write", QueryWriteOp},
	}

	for _, op := range opTypes {
		opStats := globalStats.GetOperationStats(op.op)
		min, max, avg, p95, p99, count, success, fail := opStats.GetStats()

		opData := make(map[string]interface{})
		opData["count"] = count
		opData["success_count"] = success
		opData["fail_count"] = fail
		if count > 0 {
			opData["success_rate"] = float64(success) / float64(count) * 100
		} else {
			opData["success_rate"] = 0.0
		}
		opData["min_ms"] = min.Milliseconds()
		opData["avg_ms"] = avg.Milliseconds()
		opData["max_ms"] = max.Milliseconds()
		opData["p95_ms"] = p95.Milliseconds()
		opData["p99_ms"] = p99.Milliseconds()

		operations[op.name] = opData
	}

	stats["operations"] = operations

	// Add URL statistics
	urlStats := globalStats.GetURLStats()
	urls := make(map[string]interface{})
	for url, urlStat := range urlStats {
		_, _, _, _, _, count, success, fail := urlStat.GetStats()

		urlData := make(map[string]interface{})
		urlData["count"] = count
		urlData["success_count"] = success
		urlData["fail_count"] = fail
		if count > 0 {
			urlData["success_rate"] = float64(success) / float64(count) * 100
		} else {
			urlData["success_rate"] = 0.0
		}

		urls[url] = urlData
	}
	stats["urls"] = urls

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Printf("%s\n", string(jsonData))
}

// logOperationWithURL logs an operation with URL tracking
func logOperationWithURL(opType OperationType, nodeName string, url string, latency time.Duration, success bool, config FakeNewsConfig) {
	// Record the operation in both operation and URL statistics
	globalStats.RecordOperation(opType, latency, success)
	globalStats.RecordURLOperation(url, latency, success)

	// Output based on mode
	switch config.OutputMode {
	case QuietMode:
		// No output
		return
	case SummaryMode:
		// Only periodic summaries (handled by summary goroutine)
		return
	case VerboseMode:
		fmt.Println(internaltui.FormatVerboseLine(operationName(opType), nodeName, url, latency, success))
	case DashboardMode:
		// Real-time dashboard (handled by dashboard goroutine)
		return
	case JSONMode:
		// JSON output (handled by JSON goroutine)
		return
	}
}

// summaryReporter runs periodic summary reports
func summaryReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printSummary()
		}
	}
}

func newGlobalStats() *GlobalStats {
	return &GlobalStats{
		startTime: time.Now(),
		urls: URLStats{
			stats: make(map[string]*LatencyStats),
		},
	}
}

func resetGlobalStats() {
	globalStats = newGlobalStats()
}

func aggregateSnapshot() internalmetrics.Snapshot {
	operations := []OperationType{
		EnrollOp,
		StatusOp,
		ResultOp,
		ConfigOp,
		QueryReadOp,
		QueryWriteOp,
	}

	snapshot := internalmetrics.Snapshot{}
	var weightedTotal time.Duration

	for _, op := range operations {
		min, max, avg, p95, p99, count, success, fail := globalStats.GetOperationStats(op).GetStats()
		if count == 0 {
			continue
		}

		snapshot.Count += count
		snapshot.SuccessCount += success
		snapshot.FailCount += fail
		weightedTotal += avg * time.Duration(count)

		if snapshot.Min == 0 || min < snapshot.Min {
			snapshot.Min = min
		}
		if max > snapshot.Max {
			snapshot.Max = max
		}
		if p95 > snapshot.P95 {
			snapshot.P95 = p95
		}
		if p99 > snapshot.P99 {
			snapshot.P99 = p99
		}
	}

	if snapshot.Count > 0 {
		snapshot.Avg = weightedTotal / time.Duration(snapshot.Count)
		snapshot.ErrorRate = float64(snapshot.FailCount) / float64(snapshot.Count)
	}

	return snapshot
}

func loadOrGenerateNodes(config FakeNewsConfig, r *rand.Rand) ([]Node, error) {
	if config.StateFile != "" {
		nodes, err := loadNodesFromFile(config.StateFile)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	return generateRandomNodes(config.Nodes, r), nil
}

func resolveRuntimeTargets(cfg internalconfig.Config) ([]runtimeTarget, error) {
	if cfg.ShouldDiscoverEnvs() {
		client := internaldiscovery.NewClient(cfg.APIBaseURL, internaltransport.NewDefault(cfg.Insecure))
		envs, err := client.Discover(context.Background(), cfg.APIUsername, cfg.APIPassword)
		if err != nil {
			return nil, err
		}
		targets := make([]runtimeTarget, 0, len(envs))
		for _, env := range envs {
			targets = append(targets, runtimeTarget{
				EnvUUID:   env.UUID,
				Secret:    env.Secret,
				URL:       buildEnvURL(cfg.TLSBaseURL, env.UUID),
				StateFile: deriveStateFile(cfg.StateFile, env.UUID, len(envs)),
			})
		}
		return targets, nil
	}

	return []runtimeTarget{{
		EnvUUID:   cfg.EnvUUID,
		Secret:    cfg.EnrollSecret,
		URL:       buildEnvURL(cfg.TLSBaseURL, cfg.EnvUUID),
		StateFile: cfg.StateFile,
	}}, nil
}

func buildEnvURL(baseURL, envUUID string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	envUUID = strings.Trim(strings.TrimSpace(envUUID), "/")
	return baseURL + "/" + envUUID
}

func buildURLs(envURL string) map[string]string {
	return map[string]string{
		"enroll": envURL + TLS_ENROLL,
		"log":    envURL + TLS_LOG,
		"config": envURL + TLS_CONFIG,
		"query":  envURL + TLS_QUERY_READ,
		"write":  envURL + TLS_QUERY_WRITE,
	}
}

func deriveStateFile(stateFile, envUUID string, totalTargets int) string {
	stateFile = strings.TrimSpace(stateFile)
	if stateFile == "" || totalTargets <= 1 {
		return stateFile
	}
	ext := filepath.Ext(stateFile)
	base := strings.TrimSuffix(stateFile, ext)
	return fmt.Sprintf("%s_%s%s", base, sanitizeFileToken(envUUID), ext)
}

func sanitizeFileToken(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "env"
	}
	return b.String()
}

func operationName(opType OperationType) string {
	switch opType {
	case EnrollOp:
		return "enroll"
	case StatusOp:
		return "status"
	case ResultOp:
		return "result"
	case ConfigOp:
		return "config"
	case QueryReadOp:
		return "query-read"
	case QueryWriteOp:
		return "query-write"
	default:
		return "unknown"
	}
}

func operationSnapshots() map[string]internalmetrics.Snapshot {
	ops := map[string]OperationType{
		"enroll":      EnrollOp,
		"status":      StatusOp,
		"result":      ResultOp,
		"config":      ConfigOp,
		"query-read":  QueryReadOp,
		"query-write": QueryWriteOp,
	}
	out := make(map[string]internalmetrics.Snapshot, len(ops))
	for name, op := range ops {
		min, max, avg, p95, p99, count, success, fail := globalStats.GetOperationStats(op).GetStats()
		if count == 0 {
			continue
		}
		out[name] = internalmetrics.Snapshot{
			Count:        count,
			SuccessCount: success,
			FailCount:    fail,
			ErrorRate:    float64(fail) / float64(count),
			Min:          min,
			Max:          max,
			Avg:          avg,
			P95:          p95,
			P99:          p99,
		}
	}
	return out
}

func endpointSnapshots() map[string]internalmetrics.Snapshot {
	urlStats := globalStats.GetURLStats()
	out := make(map[string]internalmetrics.Snapshot, len(urlStats))
	for url, stats := range urlStats {
		min, max, avg, p95, p99, count, success, fail := stats.GetStats()
		if count == 0 {
			continue
		}
		out[url] = internalmetrics.Snapshot{
			Count:        count,
			SuccessCount: success,
			FailCount:    fail,
			ErrorRate:    float64(fail) / float64(count),
			Min:          min,
			Max:          max,
			Avg:          avg,
			P95:          p95,
			P99:          p99,
		}
	}
	return out
}

type dashboardSession struct {
	enabled bool
	events  <-chan ui.Event
}

func newDashboardSession(enabled bool) (*dashboardSession, error) {
	if !enabled {
		return &dashboardSession{}, nil
	}
	if err := ui.Init(); err != nil {
		return nil, err
	}
	return &dashboardSession{enabled: true, events: ui.PollEvents()}, nil
}

func (d *dashboardSession) Close() {
	if d != nil && d.enabled {
		ui.Close()
	}
}

func (d *dashboardSession) Render(mode string, verdict internalmetrics.Verdict, thresholds internalmetrics.Thresholds, reportPath string, sweep internalmetrics.SweepState) {
	if d == nil || !d.enabled {
		return
	}
	grid := internaltui.Render(internaltui.ViewModel{
		Mode:       mode,
		Verdict:    verdict,
		Dashboard:  internalmetrics.NewDashboardSnapshot(aggregateSnapshot(), operationSnapshots(), endpointSnapshots(), sweep),
		Thresholds: thresholds,
		ReportPath: reportPath,
		Elapsed:    globalStats.GetUptime(),
	})
	width, height := ui.TerminalDimensions()
	grid.SetRect(0, 0, width, height)
	ui.Render(grid)
}

func (d *dashboardSession) Events() <-chan ui.Event {
	if d == nil {
		return nil
	}
	return d.events
}

func enrollNodes(client *HTTPClient, nodes []Node, secret string, urls map[string]string, config FakeNewsConfig) {
	for i := range nodes {
		if nodes[i].Key == "" {
			nodes[i].Key = enrollNode(client, nodes[i], secret, urls["enroll"], config)
		}
	}
}

func startTraffic(ctx context.Context, client *HTTPClient, nodes []Node, urls map[string]string, config FakeNewsConfig) {
	var mutex sync.Mutex

	for i := range nodes {
		go logStatus(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.StatusInterval)*time.Second, &mutex, config)
		go logResult(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.ResultInterval)*time.Second, &mutex, config)
		go configRequest(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.ConfigInterval)*time.Second, &mutex, config)
		go queryRead(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.QueryInterval)*time.Second, &mutex, config)
	}
}

func runSweep(parsedConfig internalconfig.Config, config FakeNewsConfig, client *HTTPClient, targets []runtimeTarget, dashboard *dashboardSession, signals <-chan os.Signal) error {
	reportPath := "fake_news_report.json"
	controller := internalrunner.SweepController{
		Thresholds: internalmetrics.Thresholds{
			MaxErrorRate: parsedConfig.ErrorThreshold,
			MaxP95:       parsedConfig.P95Threshold,
		},
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	highestStable := -1
	firstFailing := -1
	verdict := internalmetrics.VerdictStable
	lastTargetNodes := config.Nodes
	renderTicker := time.NewTicker(250 * time.Millisecond)
	defer renderTicker.Stop()

	for stage := 0; stage < parsedConfig.SweepStages; stage++ {
		targetNodes := parsedConfig.SweepStartNodes + (stage * parsedConfig.SweepStepNodes)
		lastTargetNodes = targetNodes * len(targets)
		stageConfig := config
		stageConfig.Nodes = targetNodes
		resetGlobalStats()

		stageCtx, cancel := context.WithCancel(context.Background())
		totalNodes := 0
		for _, target := range targets {
			stageConfig.Env = target.EnvUUID
			stageConfig.Secret = target.Secret
			stageConfig.URL = target.URL
			nodes := generateRandomNodes(targetNodes, r)
			urls := buildURLs(target.URL)
			enrollNodes(client, nodes, stageConfig.Secret, urls, stageConfig)
			startTraffic(stageCtx, client, nodes, urls, stageConfig)
			totalNodes += len(nodes)
		}
		globalStats.SetNodeCounts(totalNodes, totalNodes)

		settleUntil := time.Now().Add(parsedConfig.SettleDuration)
		for time.Now().Before(settleUntil) {
			select {
			case <-signals:
				cancel()
				return nil
			case event := <-dashboard.Events():
				if internaltui.ShouldQuitEvent(event.ID) {
					cancel()
					return nil
				}
			case <-renderTicker.C:
				dashboard.Render("sweep", verdict, controller.Thresholds, reportPath, internalmetrics.SweepState{
					Stage:              stage,
					HighestStableStage: highestStable,
					TargetNodes:        targetNodes,
					SettleRemaining:    time.Until(settleUntil),
				})
			}
		}

		resetGlobalStats()
		sampleUntil := time.Now().Add(parsedConfig.SampleDuration)
		for time.Now().Before(sampleUntil) {
			select {
			case <-signals:
				cancel()
				return nil
			case event := <-dashboard.Events():
				if internaltui.ShouldQuitEvent(event.ID) {
					cancel()
					return nil
				}
			case <-renderTicker.C:
				dashboard.Render("sweep", verdict, controller.Thresholds, reportPath, internalmetrics.SweepState{
					Stage:              stage,
					HighestStableStage: highestStable,
					TargetNodes:        targetNodes,
					SampleRemaining:    time.Until(sampleUntil),
				})
			}
		}

		snapshot := aggregateSnapshot()
		result := controller.EvaluateStages(context.Background(), []internalmetrics.Snapshot{snapshot})
		cancel()

		if result.FirstFailingStage == 0 {
			firstFailing = stage
			verdict = result.FailureReason
			break
		}

		highestStable = stage
	}

	runReport := internalreport.RunReport{
		Mode:               string(parsedConfig.Mode),
		HighestStableStage: highestStable,
		FirstFailingStage:  firstFailing,
		FailureReason:      verdict,
		Totals:             aggregateSnapshot(),
		GeneratedAt:        time.Now().UTC(),
	}
	if err := internalreport.WriteJSON(reportPath, runReport); err != nil {
		return err
	}

	dashboard.Render("sweep", verdict, controller.Thresholds, reportPath, internalmetrics.SweepState{
		Stage:              max(firstFailing, 0),
		HighestStableStage: highestStable,
		TargetNodes:        lastTargetNodes,
	})
	fmt.Println(internalreport.Summary(runReport))
	return nil
}

func run() error {
	parsedConfig, err := internalconfig.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	config := FakeNewsConfig{
		URL:             parsedConfig.TLSBaseURL,
		Env:             parsedConfig.EnvUUID,
		Secret:          parsedConfig.EnrollSecret,
		Nodes:           parsedConfig.Nodes,
		StatusInterval:  parsedConfig.StatusInterval,
		ResultInterval:  parsedConfig.ResultInterval,
		ConfigInterval:  parsedConfig.ConfigInterval,
		QueryInterval:   parsedConfig.QueryInterval,
		Verbose:         parsedConfig.Verbose,
		Insecure:        parsedConfig.Insecure,
		SummaryInterval: parsedConfig.SummaryInterval,
		StateFile:       parsedConfig.StateFile,
	}

	osqueryRunner = internalosquery.NewDefault(parsedConfig.OSQueryBinary)
	thresholds := internalmetrics.Thresholds{
		MaxErrorRate: parsedConfig.ErrorThreshold,
		MaxP95:       parsedConfig.P95Threshold,
	}

	// Parse output mode
	switch strings.ToLower(parsedConfig.OutputMode) {
	case "quiet":
		config.OutputMode = QuietMode
	case "summary":
		config.OutputMode = SummaryMode
	case "verbose":
		config.OutputMode = VerboseMode
	case "dashboard":
		config.OutputMode = DashboardMode
	case "json":
		config.OutputMode = JSONMode
	default:
		fmt.Fprintf(os.Stderr, "Error: Invalid output mode '%s'. Valid modes: quiet, summary, verbose, dashboard, json\n", parsedConfig.OutputMode)
		os.Exit(1)
	}

	// Override with verbose flag if set
	if config.Verbose {
		config.OutputMode = VerboseMode
	}

	// Append environment to URL if not present
	if !strings.HasSuffix(config.URL, "/") {
		config.URL += "/"
	}

	// Initialize random seed
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	dashboard, err := newDashboardSession(config.OutputMode == DashboardMode)
	if err != nil {
		return err
	}
	defer dashboard.Close()

	targets, err := resolveRuntimeTargets(parsedConfig)
	if err != nil {
		return err
	}
	totalNodes := len(targets) * config.Nodes
	globalStats.SetNodeCounts(totalNodes, totalNodes)
	fmt.Printf("Resolved %d environment target(s)\n", len(targets))
	for _, target := range targets {
		fmt.Printf("  - %s -> %s\n", target.EnvUUID, target.URL)
	}

	if parsedConfig.Mode == internalconfig.ModeSweep {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
		if err := runSweep(parsedConfig, config, NewHTTPClient(config.Verbose, config.Insecure), targets, dashboard, signals); err != nil {
			return err
		}
		return nil
	}

	// Create HTTP client
	client := NewHTTPClient(config.Verbose, config.Insecure)
	type targetRun struct {
		config FakeNewsConfig
		nodes  []Node
	}
	runs := make([]targetRun, 0, len(targets))
	for _, target := range targets {
		targetConfig := config
		targetConfig.Env = target.EnvUUID
		targetConfig.Secret = target.Secret
		targetConfig.URL = target.URL
		targetConfig.StateFile = target.StateFile

		nodes, err := loadOrGenerateNodes(targetConfig, r)
		if err != nil {
			return err
		}
		if config.Verbose {
			prettyJSON, _ := json.MarshalIndent(nodes, "", "  ")
			fmt.Printf("%s\n", string(prettyJSON))
		}
		enrollNodes(client, nodes, targetConfig.Secret, buildURLs(target.URL), targetConfig)
		runs = append(runs, targetRun{config: targetConfig, nodes: nodes})
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	// Periodically save state if state file is specified
	for _, run := range runs {
		if run.config.StateFile == "" {
			continue
		}
		go func(ctx context.Context, nodes []Node, stateFile string) {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := saveNodesToFile(nodes, stateFile); err != nil {
						fmt.Printf("Failed to save state: %v\n", err)
					}
				}
			}
		}(ctx, run.nodes, run.config.StateFile)
	}

	for _, run := range runs {
		startTraffic(ctx, client, run.nodes, buildURLs(run.config.URL), run.config)
	}

	// Print startup message based on output mode
	switch config.OutputMode {
	case QuietMode:
		fmt.Printf("Started %d nodes across %d environment(s) in quiet mode. Press Ctrl+C to stop.\n", totalNodes, len(targets))
	case SummaryMode:
		fmt.Printf("Started %d nodes across %d environment(s) with summary reports every %d seconds. Press Ctrl+C to stop.\n", totalNodes, len(targets), config.SummaryInterval)
	case VerboseMode:
		fmt.Println("Started concurrent traffic simulation with verbose output. Press Ctrl+C to stop.")
	case DashboardMode:
		fmt.Printf("Started %d nodes across %d environment(s) with real-time dashboard. Press Ctrl+C to stop.\n", totalNodes, len(targets))
	case JSONMode:
		fmt.Printf("Started %d nodes across %d environment(s) with JSON output every %d seconds. Press Ctrl+C to stop.\n", totalNodes, len(targets), config.SummaryInterval)
	}

	refreshInterval := 2 * time.Second
	if config.OutputMode == SummaryMode || config.OutputMode == JSONMode {
		refreshInterval = time.Duration(config.SummaryInterval) * time.Second
	}
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-signals:
			cancel()
			reportPath := "fake_news_report.json"
			runReport := internalreport.RunReport{
				Mode:               string(parsedConfig.Mode),
				HighestStableStage: 0,
				FirstFailingStage:  -1,
				FailureReason:      internalmetrics.VerdictStable,
				Totals:             aggregateSnapshot(),
				GeneratedAt:        time.Now().UTC(),
			}
			_ = internalreport.WriteJSON(reportPath, runReport)
			dashboard.Render("steady", internalmetrics.VerdictStable, thresholds, reportPath, internalmetrics.SweepState{
				TargetNodes: totalNodes,
			})
			fmt.Println(internalreport.Summary(runReport))
			return nil
		case event := <-dashboard.Events():
			if !internaltui.ShouldQuitEvent(event.ID) {
				continue
			}
			cancel()
			reportPath := "fake_news_report.json"
			runReport := internalreport.RunReport{
				Mode:               string(parsedConfig.Mode),
				HighestStableStage: 0,
				FirstFailingStage:  -1,
				FailureReason:      internalmetrics.VerdictStable,
				Totals:             aggregateSnapshot(),
				GeneratedAt:        time.Now().UTC(),
			}
			_ = internalreport.WriteJSON(reportPath, runReport)
			dashboard.Render("steady", internalmetrics.VerdictStable, thresholds, reportPath, internalmetrics.SweepState{
				TargetNodes: totalNodes,
			})
			fmt.Println(internalreport.Summary(runReport))
			return nil
		case <-ticker.C:
			switch config.OutputMode {
			case SummaryMode:
				printSummary()
			case DashboardMode:
				dashboard.Render("steady", internalmetrics.VerdictStable, thresholds, "fake_news_report.json", internalmetrics.SweepState{
					TargetNodes: totalNodes,
				})
			case JSONMode:
				printJSONStats()
			}
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
