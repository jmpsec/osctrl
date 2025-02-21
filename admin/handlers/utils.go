package handlers

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

const (
	QueryLink   string = "/query/{{ENV}}/logs/{{NAME}}"
	StatusLink  string = "#status-logs"
	ResultsLink string = "#result-logs"
)

// Helper to handle admin error responses
func adminErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Err(err).Msgf("%d:%s", code, msg)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, AdminResponse{Message: msg})
}

// Helper to handle admin ok responses
func adminOKResponse(w http.ResponseWriter, msg string) {
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: msg})
}

// Helper to verify if a platform is valid
func checkValidPlatform(platforms []string, platform string) bool {
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
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

// Helper to generate the carve query
func generateCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + file + "';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + file + "';"
}

// Helper to determine if a query may be a carve
func newQueryReady(user, query string, exp time.Time, envid uint) queries.DistributedQuery {
	if strings.Contains(query, "carve(") || strings.Contains(query, "carve=1") {
		return queries.DistributedQuery{
			Query:         query,
			Name:          generateCarveName(),
			Creator:       user,
			Expected:      0,
			Executions:    0,
			Active:        true,
			Completed:     false,
			Deleted:       false,
			Expired:       false,
			Expiration:    exp,
			Type:          queries.CarveQueryType,
			Path:          query,
			EnvironmentID: envid,
		}
	}
	return queries.DistributedQuery{
		Query:         query,
		Name:          generateQueryName(),
		Creator:       user,
		Expected:      0,
		Executions:    0,
		Active:        true,
		Completed:     false,
		Deleted:       false,
		Expired:       false,
		Expiration:    exp,
		Type:          queries.StandardQueryType,
		EnvironmentID: envid,
	}
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

// Helper to remove backslashes from text
func removeBackslash(rawString string) string {
	return strings.ReplaceAll(rawString, "\\", " ")
}

// Helper to convert string into indented string
func jsonRawIndent(raw string) string {
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(raw), "", "    "); err != nil {
		return string(raw)
	}
	return string(out.Bytes())
}

// Helper to convert from settings values to JSON configuration
func toJSONConfigurationService(values []settings.SettingValue) types.JSONConfigurationAdmin {
	var cfg types.JSONConfigurationAdmin
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
		if v.Name == settings.JSONLogger {
			cfg.Logger = v.String
		}
		if v.Name == settings.JSONCarver {
			cfg.Carver = v.String
		}
		if v.Name == settings.JSONSessionKey {
			cfg.SessionKey = v.String
		}
	}
	return cfg
}

// Helper to generate a link to results for on-demand queries
func (h *HandlersAdmin) queryResultLink(name string, env string) string {
	replacer := strings.NewReplacer("{{ENV}}", env, "{{NAME}}", removeBackslash(name))
	return replacer.Replace(QueryLink)
}

// Helper to convert the list of all TLS environments with the ones with permissions for a user
func (h *HandlersAdmin) allowedEnvironments(username string, allEnvs []environments.TLSEnvironment) []environments.TLSEnvironment {
	var envs []environments.TLSEnvironment
	for _, e := range allEnvs {
		if h.Users.CheckPermissions(username, users.UserLevel, e.UUID) {
			envs = append(envs, e)
		}
	}
	return envs
}

// Helper to generate flags with the correct paths for secret file and certificate
func (h *HandlersAdmin) generateFlags(flagsRaw, secretFile, certFile string) string {
	replaced := strings.Replace(flagsRaw, "__SECRET_FILE__", secretFile, 1)
	return strings.Replace(replaced, "__CERT_FILE__", certFile, 1)
}
