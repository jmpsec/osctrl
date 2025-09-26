package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

	NODES_JSON = "nodes.json"
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

// GlobalStats holds global statistics
type GlobalStats struct {
	mu          sync.RWMutex
	operations  OperationStats
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
		"5.1.0", "5.3.0", "4.8.2", "5.19.0",
	}

	// Global statistics instance
	globalStats = &GlobalStats{
		startTime: time.Now(),
	}
)

// Node represents a simulated osctrl node
type Node struct {
	Target     string `json:"target"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Identifier string `json:"identifier"`
	Key        string `json:"key"`
}

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
	ReadFile        string
	WriteFile       string
	Verbose         bool
	OutputMode      OutputMode
	SummaryInterval int
}

// HTTPClient wraps http.Client with custom configuration
type HTTPClient struct {
	client *http.Client
	debug  bool
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(debug bool) *HTTPClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &HTTPClient{
		client: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
		debug: debug,
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

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if c.debug {
		fmt.Printf("HTTP %d\n", resp.StatusCode)
	}

	var result map[string]interface{}
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(body, &result); err != nil {
			return resp.StatusCode, nil, err
		}
		if c.debug {
			prettyJSON, _ := json.MarshalIndent(result, "", "  ")
			fmt.Printf("%s\n", string(prettyJSON))
		}
	}

	return resp.StatusCode, result, nil
}

// generateRandomIP generates a random IP address
func generateRandomIP() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%d.%d.%d.%d",
		r.Intn(256),
		r.Intn(256),
		r.Intn(256),
		r.Intn(256))
}

// generateHostname generates a hostname based on platform
func generateHostname(platform string) string {
	suffixes := []string{"Prod", "Legacy", "Test", "Dev", "PC"}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	suffix := suffixes[r.Intn(len(suffixes))]
	titleCaser := cases.Title(language.English)
	return fmt.Sprintf("%s-%s", titleCaser.String(platform), suffix)
}

// generateRandomNode generates a random node
func generateRandomNode() Node {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	platform := platforms[r.Intn(len(platforms))]
	return Node{
		Target:     platform,
		IP:         generateRandomIP(),
		Name:       generateHostname(platform),
		Version:    osqueryVersions[r.Intn(len(osqueryVersions))],
		Identifier: uuid.New().String(),
		Key:        "",
	}
}

// generateRandomNodes generates n random nodes
func generateRandomNodes(n int) []Node {
	nodes := make([]Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = generateRandomNode()
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
	cmd := exec.Command(OSQUERYI, "--json", query)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, err
	}

	return results, nil
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
	logOperation(EnrollOp, node.Name, requestTime, success, config)

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
			logOperation(StatusOp, node.Name, requestTime, success, config)

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
			logOperation(ResultOp, node.Name, requestTime, success, config)

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
			logOperation(ConfigOp, node.Name, requestTime, success, config)

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
			logOperation(QueryReadOp, node.Name, requestTime, success, config)

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
	logOperation(QueryWriteOp, node.Name, requestTime, success, config)

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

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Printf("%s\n", string(jsonData))
}

// logOperation logs an operation based on the output mode
func logOperation(opType OperationType, nodeName string, latency time.Duration, success bool, config FakeNewsConfig) {
	// Record the operation in statistics
	globalStats.RecordOperation(opType, latency, success)

	// Output based on mode
	switch config.OutputMode {
	case QuietMode:
		// No output
		return
	case SummaryMode:
		// Only periodic summaries (handled by summary goroutine)
		return
	case VerboseMode:
		// Original verbose output
		opNames := map[OperationType]string{
			EnrollOp:     "enroll",
			StatusOp:     "status",
			ResultOp:     "result",
			ConfigOp:     "config",
			QueryReadOp:  "query_read",
			QueryWriteOp: "query_write",
		}
		status := "✓"
		if !success {
			status = "✗"
		}
		fmt.Printf("⏰ %d ms %s %s from %s\n", latency.Milliseconds(), status, opNames[opType], nodeName)
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

// dashboardReporter runs real-time dashboard updates
func dashboardReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printDashboard()
		}
	}
}

// jsonReporter runs periodic JSON output
func jsonReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printJSONStats()
		}
	}
}

func main() {
	// Command line flags
	var config FakeNewsConfig

	flag.StringVar(&config.URL, "url", TLS_URL, "URL for osctrl-tls used to enroll nodes")
	flag.StringVar(&config.URL, "u", TLS_URL, "URL for osctrl-tls used to enroll nodes")
	flag.StringVar(&config.Env, "environment", "", "Environment UUID for osctrl-tls")
	flag.StringVar(&config.Secret, "secret", "", "Secret to enroll nodes for osctrl-tls")
	flag.StringVar(&config.Secret, "s", "", "Secret to enroll nodes for osctrl-tls")
	flag.IntVar(&config.Nodes, "nodes", 5, "Number of random nodes to simulate")
	flag.IntVar(&config.Nodes, "n", 5, "Number of random nodes to simulate")
	flag.IntVar(&config.StatusInterval, "status", LOG_INTERVAL, "Interval in seconds for status requests to osctrl")
	flag.IntVar(&config.StatusInterval, "S", LOG_INTERVAL, "Interval in seconds for status requests to osctrl")
	flag.IntVar(&config.ResultInterval, "result", LOG_INTERVAL, "Interval in seconds for result requests to osctrl")
	flag.IntVar(&config.ResultInterval, "R", LOG_INTERVAL, "Interval in seconds for result requests to osctrl")
	flag.IntVar(&config.ConfigInterval, "config", CONFIG_INTERVAL, "Interval in seconds for config requests to osctrl")
	flag.IntVar(&config.ConfigInterval, "c", CONFIG_INTERVAL, "Interval in seconds for config requests to osctrl")
	flag.IntVar(&config.QueryInterval, "query", QUERY_READ_INTERVAL, "Interval in seconds for query requests to osctrl")
	flag.IntVar(&config.QueryInterval, "q", QUERY_READ_INTERVAL, "Interval in seconds for query requests to osctrl")
	flag.StringVar(&config.ReadFile, "read", "", "JSON file to read nodes from")
	flag.StringVar(&config.ReadFile, "r", "", "JSON file to read nodes from")
	flag.StringVar(&config.WriteFile, "write", "", "JSON file to write nodes to")
	flag.StringVar(&config.WriteFile, "w", "", "JSON file to write nodes to")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose output")

	// Output mode flags
	var outputMode string
	flag.StringVar(&outputMode, "mode", "summary", "Output mode: quiet, summary, verbose, dashboard, json")
	flag.IntVar(&config.SummaryInterval, "summary-interval", 30, "Interval in seconds for summary reports")

	flag.Parse()

	// Parse output mode
	switch strings.ToLower(outputMode) {
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
		fmt.Fprintf(os.Stderr, "Error: Invalid output mode '%s'. Valid modes: quiet, summary, verbose, dashboard, json\n", outputMode)
		os.Exit(1)
	}

	// Override with verbose flag if set
	if config.Verbose {
		config.OutputMode = VerboseMode
	}

	// Check required parameters
	if config.Secret == "" {
		fmt.Fprintf(os.Stderr, "Error: --secret is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if config.Env == "" {
		fmt.Fprintf(os.Stderr, "Error: --environment is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Append environment to URL if not present
	if !strings.HasSuffix(config.URL, "/") {
		config.URL += "/"
	}
	if !strings.Contains(config.URL, config.Env) {
		config.URL += config.Env
	}

	// Print configuration
	fmt.Printf("Using URL %s\n", config.URL)
	fmt.Printf("Using secret %s\n", config.Secret)

	// Build URLs
	urls := map[string]string{
		"enroll": config.URL + TLS_ENROLL,
		"log":    config.URL + TLS_LOG,
		"config": config.URL + TLS_CONFIG,
		"query":  config.URL + TLS_QUERY_READ,
		"write":  config.URL + TLS_QUERY_WRITE,
	}

	// Load or generate nodes
	var nodes []Node
	var err error

	if config.ReadFile != "" {
		fmt.Printf("Reading from JSON %s\n", config.ReadFile)
		nodes, err = loadNodesFromFile(config.ReadFile)
		if err != nil {
			log.Fatalf("Failed to load nodes from file: %v", err)
		}
	} else {
		fmt.Printf("Generating %d nodes\n", config.Nodes)
		nodes = generateRandomNodes(config.Nodes)
	}

	if config.Verbose {
		prettyJSON, _ := json.MarshalIndent(nodes, "", "  ")
		fmt.Printf("%s\n", string(prettyJSON))
	}

	// Create HTTP client
	client := NewHTTPClient(config.Verbose)

	// Enroll nodes
	for i := range nodes {
		fmt.Printf("Enrolling %s as %s\n", nodes[i].Target, nodes[i].Name)
		nodes[i].Key = enrollNode(client, nodes[i], config.Secret, urls["enroll"], config)
	}

	// Save nodes to file if requested
	if config.WriteFile != "" {
		fmt.Printf("Writing to JSON %s\n", config.WriteFile)
		if err := saveNodesToFile(nodes, config.WriteFile); err != nil {
			log.Fatalf("Failed to save nodes to file: %v", err)
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create mutex for thread-safe node updates
	var mutex sync.Mutex

	// Set node counts in global stats
	globalStats.SetNodeCounts(len(nodes), len(nodes))

	// Start monitoring goroutines based on output mode
	switch config.OutputMode {
	case SummaryMode:
		go summaryReporter(ctx, time.Duration(config.SummaryInterval)*time.Second)
	case DashboardMode:
		go dashboardReporter(ctx, 2*time.Second) // Update every 2 seconds
	case JSONMode:
		go jsonReporter(ctx, time.Duration(config.SummaryInterval)*time.Second)
	}

	// Start concurrent traffic with goroutines
	for i := range nodes {
		// Status log goroutine
		go logStatus(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.StatusInterval)*time.Second, &mutex, config)

		// Result log goroutine
		go logResult(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.ResultInterval)*time.Second, &mutex, config)

		// Config goroutine
		go configRequest(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.ConfigInterval)*time.Second, &mutex, config)

		// Query read goroutine
		go queryRead(ctx, client, &nodes[i], urls, config.Secret,
			time.Duration(config.QueryInterval)*time.Second, &mutex, config)
	}

	// Print startup message based on output mode
	switch config.OutputMode {
	case QuietMode:
		fmt.Printf("Started %d nodes in quiet mode. Press Ctrl+C to stop.\n", len(nodes))
	case SummaryMode:
		fmt.Printf("Started %d nodes with summary reports every %d seconds. Press Ctrl+C to stop.\n", len(nodes), config.SummaryInterval)
	case VerboseMode:
		fmt.Println("Started concurrent traffic simulation with verbose output. Press Ctrl+C to stop.")
	case DashboardMode:
		fmt.Printf("Started %d nodes with real-time dashboard. Press Ctrl+C to stop.\n", len(nodes))
	case JSONMode:
		fmt.Printf("Started %d nodes with JSON output every %d seconds. Press Ctrl+C to stop.\n", len(nodes), config.SummaryInterval)
	}

	// Wait for interrupt signal
	select {}
}
