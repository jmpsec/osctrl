package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

// Constants for seconds
const (
	oneMinute        = 60
	fiveMinutes      = 300
	fifteenMinutes   = 900
	thirtyMinutes    = 1800
	fortyfiveMinutes = 2500
	oneHour          = 3600
	threeHours       = 10800
	sixHours         = 21600
	eightHours       = 28800
	twelveHours      = 43200
	fifteenHours     = 54000
	twentyHours      = 72000
	oneDay           = 86400
	twoDays          = 172800
	sevenDays        = 604800
	fifteenDays      = 1296000
)

// Helper to get environment variables
func getServerEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Function to generate a secure CSRF token
func generateCSRF() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to check if the CSRF token is valid
func checkCSRFToken(token string) bool {
	//return (strings.TrimSpace(token) == mainCSRFToken)
	return true
}

// Helper to generate a random enough node key
func generateNodeKey(UUID string) string {
	timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	hasher := md5.New()
	hasher.Write([]byte(UUID + timestamp))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to generate a random MD5 to be used as query name
func generateQueryName() string {
	b := make([]byte, 32)
	rand.Read(b)
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%x", b)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to check if the provided secret is valid for this context
func checkValidSecret(enrollSecret string, context string) bool {
	ctx, err := getContext(context)
	if err != nil {
		return false
	}
	return (strings.TrimSpace(enrollSecret) == ctx.Secret)
}

// Helper to check if the provided platform exists
func checkValidPlatform(platform string) bool {
	platforms, err := getAllPlatforms()
	if err != nil {
		return false
	}
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// Helper to check if the provided SecretPath is valid for a context
func checkValidSecretPath(context, secretpath string) bool {
	ctx, err := getContext(context)
	if err != nil {
		return false
	}
	return (strings.TrimSpace(secretpath) == ctx.SecretPath)
}

// Helper to convert an enrollment request into a osquery node
func nodeFromEnroll(req EnrollRequest, context, ipaddress, nodekey string) OsqueryNode {
	// Prepare the enrollment request to be stored as JSON
	enrollRaw, err := json.Marshal(req)
	if err != nil {
		log.Printf("error serializing enrollment: %v", err)
		enrollRaw = []byte("")
	}
	// Avoid the error "unsupported Unicode escape sequence" due to \u0000
	enrollRaw = bytes.Replace(enrollRaw, []byte("\\u0000"), []byte(""), -1)
	return OsqueryNode{
		NodeKey:         nodekey,
		UUID:            req.HostIdentifier,
		Platform:        req.HostDetails.EnrollOSVersion.Platform,
		PlatformVersion: req.HostDetails.EnrollOSVersion.Version,
		OsqueryVersion:  req.HostDetails.EnrollOsqueryInfo.Version,
		Hostname:        req.HostDetails.EnrollSystemInfo.Hostname,
		Localname:       req.HostDetails.EnrollSystemInfo.LocalHostname,
		IPAddress:       ipaddress,
		Username:        "unknown",
		OsqueryUser:     "unknown",
		Context:         context,
		CPU:             strings.TrimRight(req.HostDetails.EnrollSystemInfo.CPUBrand, "\x00"),
		Memory:          req.HostDetails.EnrollSystemInfo.PhysicalMemory,
		HardwareSerial:  req.HostDetails.EnrollSystemInfo.HardwareSerial,
		ConfigHash:      req.HostDetails.EnrollOsqueryInfo.ConfigHash,
		RawEnrollment:   enrollRaw,
		LastStatus:      time.Time{},
		LastResult:      time.Time{},
		LastConfig:      time.Time{},
		LastQueryRead:   time.Time{},
		LastQueryWrite:  time.Time{},
	}
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
		Context:         node.Context,
		CPU:             node.CPU,
		Memory:          node.Memory,
		HardwareSerial:  node.HardwareSerial,
		ConfigHash:      node.ConfigHash,
		RawEnrollment:   node.RawEnrollment,
		LastStatus:      node.LastStatus,
		LastResult:      node.LastResult,
		LastConfig:      node.LastConfig,
		LastQueryRead:   node.LastQueryRead,
		LastQueryWrite:  node.LastQueryWrite,
	}
}

// Helper to retrieve the osquery configuration
// FIXME use cache for this to avoid too much I/O
func getOsqueryConfiguration(filePath string) (string, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	// Scan file line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	// Iterate through lines to remove end of lines and other spaces
	var lines []string
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	blob := strings.Join(lines, "")
	// FIXME do this better, to make sure there are no spaces in the JSON
	// JSON can have fields like "key: " or "key :value"
	return strings.Replace(strings.Replace(blob, ": ", ":", -1), " :", ":", -1), nil
}

// Helper for debugging purposes and dump a full HTTP request
func debugHTTPDump(r *http.Request, debugCheck bool, showBody bool) {
	if debugCheck {
		log.Println("-------------------------------------------------- request")
		requestDump, err := httputil.DumpRequest(r, showBody)
		if err != nil {
			log.Printf("error while dumprequest %v", err)
		}
		log.Println(string(requestDump))
		if !showBody {
			log.Println("---------------- Skipping Request Body -------------------")
		}
		log.Println("-------------------------------------------------------end")
	}
}

// Helper to escape text
func escapeText(rawString string) string {
	return html.EscapeString(rawString)
}

// Helper to remove backslashes from text
func removeBackslash(rawString string) string {
	return strings.Replace(rawString, "\\", " ", -1)
}

// Helper to remove backslashes from text and encode
func removeBackslashEncode(data []byte) string {
	return strings.Replace(string(data), "\\", " ", -1)
}

// Helper to remove backslashes from text
func stringEncode(data []byte) string {
	return string(data)
}

// Helper to remove backslashes and truncate
func noBackslashTruncate(rawString string) string {
	return removeBackslash(rawString)[:12]
}

// Helper to generate a link to results for on-demand queries
func resultsSearchLink(name string) string {
	if logConfig.Splunk {
		return strings.Replace(logConfig.SplunkCfg["search"], "{{NAME}}", removeBackslash(name), 1)
	}
	if logConfig.Postgres {
		return "/query/logs/" + removeBackslash(name)
	}
	return ""
}

// Helper to get a string based on the difference of two times
func stringifyTime(seconds int) string {
	var timeStr string
	w := make(map[int]string)
	w[oneDay] = "day"
	w[oneHour] = "hour"
	w[oneMinute] = "minute"
	// Ordering the values will prevent bad values
	var ww [3]int
	ww[0] = oneDay
	ww[1] = oneHour
	ww[2] = oneMinute
	for _, v := range ww {
		if seconds >= v {
			d := seconds / v
			dStr := strconv.Itoa(d)
			timeStr = dStr + " " + w[v]
			if d > 1 {
				timeStr += "s"
			}
			break
		}
	}
	return timeStr + " ago"
}

// Helper to get a string based on the difference of two times
func stringifyTimeFull(seconds int) string {
	var timeStr string
	w := make(map[int]string)
	w[oneDay] = "day"
	w[oneHour] = "hour"
	w[oneMinute] = "minute"
	// Ordering the values will prevent bad values
	var ww [3]int
	ww[0] = oneDay
	ww[1] = oneHour
	ww[2] = oneMinute
	secondsTime := seconds
	for _, v := range ww {
		if seconds >= v {
			d := seconds / v
			timeStr += strconv.Itoa(d) + " " + w[v]
			if d > 1 {
				timeStr += "s"
			}
			secondsTime = secondsTime - (v * d)
		}
	}
	return timeStr + " ago"
}

func stringifySeconds(seconds int) string {
	timeStr := ""
	if seconds < 60 {
		return strconv.Itoa(seconds) + " seconds"
	}
	return timeStr
}

// Helper to format past times in seconds
func pastSeconds(t time.Time) string {
	now := time.Now()
	seconds := int(now.Sub(t).Seconds())
	return strconv.Itoa(seconds)
}

// Helper to format past times in timestamp format
func pastTimestamp(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// Helper to format past times only returning one value (minute, hour, day)
func pastTimeAgo(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	now := time.Now()
	seconds := int(now.Sub(t).Seconds())
	if seconds < 2 {
		return "Just Now"
	}
	if seconds < oneMinute {
		return strconv.Itoa(seconds) + " seconds ago"
	}
	if seconds > fifteenDays {
		return "Since " + t.Format("Mon Jan 02 15:04:05 MST 2006")
	}
	return stringifyTime(seconds)
}

// Helper function to send HTTP requests
func sendRequest(secure bool, reqType, url string, params io.Reader, headers map[string]string) (int, []byte, error) {
	var client *http.Client
	if secure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}
	req, err := http.NewRequest(reqType, url, params)
	if err != nil {
		return 0, []byte("Cound not prepare request"), err
	}
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}

	return resp.StatusCode, bodyBytes, nil
}

// Helper to generate stats for all contexts
func getContextStats(contexts []TLSContext) (StatsData, error) {
	contextStats := make(StatsData)
	for _, c := range contexts {
		stats, err := getNodeStatsByContext(c.Name)
		if err != nil {
			return contextStats, err
		}
		contextStats[c.Name] = stats
	}
	return contextStats, nil
}

// Helper to generate stats for all platforms
func getPlatformStats(platforms []string) (StatsData, error) {
	platformStats := make(StatsData)
	for _, p := range platforms {
		stats, err := getNodeStatsByPlatform(p)
		if err != nil {
			return platformStats, err
		}
		platformStats[p] = stats
	}
	return platformStats, nil
}

// Helper to remove duplicates from array of strings
func uniq(duplicated []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, entry := range duplicated {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}

// Helper to verify login credentials
func checkLoginCredentials(user, pass string) (bool, LocalAuthUser) {
	if u, ok := localUsers[user]; ok {
		if u.Password == pass {
			return true, u
		}
	}
	return false, LocalAuthUser{}
}

// Helper to calculate the osquery config_hash and skip sending a blob that won't change anything
// https://github.com/facebook/osquery/blob/master/osquery/config/config.cpp#L911
// osquery calculates the SHA1 of the configuration blob, then the SHA1 hash of that
func generateOsqueryConfigHash(config string) string {
	firstHasher := sha1.New()
	secondHasher := sha1.New()
	// Get SHA1 of configuration blob
	firstHasher.Write([]byte(config))
	// Get SHA1 of the first hash
	secondHasher.Write([]byte(hex.EncodeToString(firstHasher.Sum(nil))))
	return hex.EncodeToString(secondHasher.Sum(nil))
}

// Helper to decide whether if the query targets apply to a give node
func isQueryTarget(node OsqueryNode, targets []DistributedQueryTarget) bool {
	for _, t := range targets {
		// Check for context match
		if t.Type == queryTargetContext && node.Context == t.Value {
			return true
		}
		// Check for platform match
		if t.Type == queryTargetPlatform && node.Platform == t.Value {
			return true
		}
		// Check for UUID match
		if t.Type == queryTargetUUID && node.UUID == t.Value {
			return true
		}
		// Check for localname match
		if t.Type == queryTargetLocalname && node.Localname == t.Value {
			return true
		}
	}
	return false
}

// Helper to determine if an IPv4 is public, based on the following:
// Class   Starting IPAddress  Ending IPAddress
// A       		10.0.0.0       	 10.255.255.255
// B       		172.16.0.0       172.31.255.255
// C       		192.168.0.0      192.168.255.255
// Link-local 169.254.0.0      169.254.255.255
// Local      127.0.0.0        127.255.255.255
func isPublicIP(IP net.IP) bool {
	// Use native functions
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	// Check each octet
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}

// Helper to compose the Google Maps API URL including the key
func getGoogleMapsURL() string {
	return strings.Replace(geolocConfig.GoogleMapsCfg["api"], "{{APIKEY}}", geolocConfig.GoogleMapsCfg["apikey"], 1)
}
