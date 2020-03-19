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

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/utils"
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
func queryResultLink(name string) (string, string) {
	defaultLink := strings.Replace(settings.QueryLink, "{{NAME}}", removeBackslash(name), 1)
	dbLink := strings.Replace(settingsmgr.QueryResultLink(), "{{NAME}}", removeBackslash(name), 1)
	return defaultLink, dbLink
}

// Helper to generate a link to results for status logs
func statusLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.StatusLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
}

// Helper to generate a link to results for result logs
func resultLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.ResultLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
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

// Helper to verify the service is valid
func checkTargetService(service string) bool {
	if service == settings.ServiceTLS {
		return true
	}
	if service == settings.ServiceAdmin {
		return true
	}
	if service == settings.ServiceAPI {
		return true
	}
	return false
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
		APIDebug:       settingsmgr.DebugService(settings.ServiceAPI),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
		APIDebugHTTP:   settingsmgr.DebugHTTP(settings.ServiceAPI),
	}
}

// Helper to handle admin error responses
func adminErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Printf("%s: %v", msg, err)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, AdminResponse{Message: msg})
}

// Helper to handle admin ok responses
func adminOKResponse(w http.ResponseWriter, msg string) {
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: msg})
}
