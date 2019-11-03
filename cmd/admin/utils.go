package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// Constants for seconds
const (
	oneMinute = 60
	//fiveMinutes      = 300
	//fifteenMinutes   = 900
	//thirtyMinutes    = 1800
	//fortyfiveMinutes = 2500
	oneHour = 3600
	//threeHours       = 10800
	sixHours = 21600
	//eightHours       = 28800
	//twelveHours      = 43200
	//fifteenHours     = 54000
	//twentyHours      = 72000
	oneDay = 86400
	//twoDays          = 172800
	//sevenDays        = 604800
	fifteenDays = 1296000
)

// Function to generate a secure CSRF token
func generateCSRF() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to check if the CSRF token is valid
func checkCSRFToken(ctxToken, receivedToken string) bool {
	return (strings.TrimSpace(ctxToken) == strings.TrimSpace(receivedToken))
}

// Helper to generate a random query name
func generateQueryName() string {
	return "query_" + randomForNames()
}

// Helper to generate a random carve name
func generateCarveName() string {
	return "carve_" + randomForNames()
}

// Helper to generate a random MD5 to be used with queries/carves
func randomForNames() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	hasher := md5.New()
	_, _ = hasher.Write([]byte(fmt.Sprintf("%x", b)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to determine if a query may be a carve
func newQueryReady(user, query string) queries.DistributedQuery {
	if strings.Contains(query, "carve(") || strings.Contains(query, "carve=1") {
		return queries.DistributedQuery{
			Query:      query,
			Name:       generateCarveName(),
			Creator:    user,
			Expected:   0,
			Executions: 0,
			Active:     true,
			Completed:  false,
			Deleted:    false,
			Type:       queries.CarveQueryType,
			Path:       query,
		}
	}
	return queries.DistributedQuery{
		Query:      query,
		Name:       generateQueryName(),
		Creator:    user,
		Expected:   0,
		Executions: 0,
		Active:     true,
		Completed:  false,
		Deleted:    false,
		Type:       queries.StandardQueryType,
	}
}

// Helper to generate the carve query
func generateCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + file + "';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + file + "';"
}

// Helper to verify if a platform is valid
func checkValidPlatform(platform string) bool {
	platforms, err := nodesmgr.GetAllPlatforms()
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

// Helper to remove backslashes from text
func removeBackslash(rawString string) string {
	return strings.Replace(rawString, "\\", " ", -1)
}

// Helper to generate a link to results for on-demand queries
func queryResultLink(name string) string {
	return strings.Replace(settingsmgr.QueryResultLink(), "{{NAME}}", removeBackslash(name), 1)
}

// Helper to generate a link to results for status logs
func statusLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.StatusLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
}

// Helper to generate a link to results for result logs
func resultLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.ResultLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
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
	return timeStr
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
	return stringifyTime(seconds) + " ago"
}

// Helper to format future times only returning one value (minute, hour, day)
func inFutureTime(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	now := time.Now()
	seconds := int(t.Sub(now).Seconds())
	if seconds <= 0 {
		return "Expired"
	}
	return "Expires in " + stringifyTime(seconds)
}

// Helper to calculate the osquery config_hash and skip sending a blob that won't change anything
// https://github.com/facebook/osquery/blob/master/osquery/config/config.cpp#L911
// osquery calculates the SHA1 of the configuration blob, then the SHA1 hash of that
/*
func generateOsqueryConfigHash(config string) string {
	firstHasher := sha1.New()
	secondHasher := sha1.New()
	// Get SHA1 of configuration blob
	_, _ = firstHasher.Write([]byte(config))
	// Get SHA1 of the first hash
	_, _ = secondHasher.Write([]byte(hex.EncodeToString(firstHasher.Sum(nil))))
	return hex.EncodeToString(secondHasher.Sum(nil))
}
*/

// Helper to convert a string into integer
func stringToInteger(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// Helper to convert a string into boolean
func stringToBoolean(s string) bool {
	if s == "yes" || s == "true" || s == "1" {
		return true
	}
	return false
}

// Helper to remove duplicates from []string
func removeStringDuplicates(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	i := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[i] = v
		i++
	}
	return s[:i]
}

// Helper to convert from settings values to JSON configuration
func toJSONConfigurationService(values []settings.SettingValue) types.JSONConfigurationService {
	var cfg types.JSONConfigurationService
	for _, v := range values {
		if v.Name == settings.JSONListener {
			cfg.Listener = v.String
		}
		if v.Name == settings.JSONPort {
			cfg.Port = v.String
		}
		if v.Name == settings.JSONHost {
			cfg.Host = v.String
		}
		if v.Name == settings.JSONAuth {
			cfg.Auth = v.String
		}
		if v.Name == settings.JSONLogging {
			cfg.Logging = v.String
		}
	}
	return cfg
}

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if _metrics != nil && settingsmgr.ServiceMetrics(settings.ServiceAdmin) {
		_metrics.Inc(name)
	}
}

// Helper to convert json.RawMessage into indented string
func jsonRawIndent(raw json.RawMessage) string {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "    "); err != nil {
		return string(raw)
	}
	return string(out.Bytes())
}

// Usage for service binary
func adminUsage() {
	fmt.Printf("NAME:\n   %s - %s\n\n", serviceName, serviceDescription)
	fmt.Printf("USAGE: %s [global options] [arguments...]\n\n", serviceName)
	fmt.Printf("VERSION:\n   %s\n\n", serviceVersion)
	fmt.Printf("DESCRIPTION:\n   %s\n\n", appDescription)
	fmt.Printf("GLOBAL OPTIONS:\n")
	flag.PrintDefaults()
	fmt.Printf("\n")
}

// Display binary version
func adminVersion() {
	fmt.Printf("%s v%s\n", serviceName, serviceVersion)
	os.Exit(0)
}

// Function to load the JSON data for osquery tables
func loadOsqueryTables(file string) ([]OsqueryTable, error) {
	var tables []OsqueryTable
	jsonFile, err := os.Open(file)
	if err != nil {
		return tables, err
	}
	//defer jsonFile.Close()
	defer func() {
		err := jsonFile.Close()
		if err != nil {
			log.Fatalf("Failed to close tables file %v", err)
		}
	}()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &tables)
	if err != nil {
		return tables, err
	}
	// Add a string for platforms to be used as filter
	for i, t := range tables {
		filter := ""
		for _, p := range t.Platforms {
			filter += " filter-" + p
		}
		tables[i].Filter = strings.TrimSpace(filter)
	}
	return tables, nil
}

// Helper to parse JWT tokens because the SAML library is total garbage
func parseJWTFromCookie(keypair tls.Certificate, cookie string) (JWTData, error) {
	type TokenClaims struct {
		jwt.StandardClaims
		Attributes map[string][]string `json:"attr"`
	}
	tokenClaims := TokenClaims{}
	token, err := jwt.ParseWithClaims(cookie, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
		secretBlock := x509.MarshalPKCS1PrivateKey(keypair.PrivateKey.(*rsa.PrivateKey))
		return secretBlock, nil
	})
	if err != nil || !token.Valid {
		return JWTData{}, err
	}
	return JWTData{
		Subject:  tokenClaims.Subject,
		Email:    tokenClaims.Attributes["mail"][0],
		Display:  tokenClaims.Attributes["displayName"][0],
		Username: tokenClaims.Attributes["sAMAccountName"][0],
	}, nil
}

// Helper to prepare template metadata
func templateMetadata(ctx contextValue, service, version string) TemplateMetadata {
	return TemplateMetadata{
		Username:       ctx[ctxUser],
		Level:          ctx[ctxLevel],
		CSRFToken:      ctx[ctxCSRF],
		Service:        service,
		Version:        version,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
}

// Helper to send HTTP response
func apiHTTPResponse(w http.ResponseWriter, cType string, code int, data interface{}) {
	if cType != "" {
		w.Header().Set(contentType, cType)
	}
	content, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("error serializing response: %v", err)
		content = []byte("error serializing response")
	}
	w.WriteHeader(code)
	_, _ = w.Write(content)
}

// Helper to handle admin error responses
func adminErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Printf("%s: %v", msg, err)
	apiHTTPResponse(w, JSONApplicationUTF8, code, AdminResponse{Message: msg})
}
