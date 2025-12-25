package handlers

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
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
	_, _ = fmt.Fprintf(hasher, "%x", b)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to generate the carve query
func generateCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + file + "';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + file + "';"
}

// Helper to generate the file carve query
func newCarveReady(user, path string, exp time.Time, envid uint, req DistributedQueryRequest) queries.DistributedQuery {
	return queries.DistributedQuery{
		Query:         generateCarveQuery(path, false),
		Name:          generateCarveName(),
		Creator:       user,
		Active:        true,
		Expiration:    exp,
		Type:          queries.CarveQueryType,
		Path:          path,
		EnvironmentID: envid,
		Target:        genTargetString(req.Environments, req.UUIDs, req.Hosts, req.Tags, req.Platforms),
	}
}

// Helper to determine if a query may be a carve
func newQueryReady(user, query string, exp time.Time, envid uint, req DistributedQueryRequest) queries.DistributedQuery {
	if strings.Contains(query, "carve") {
		return newCarveReady(user, query, exp, envid, req)
	}
	return queries.DistributedQuery{
		Query:         query,
		Name:          generateQueryName(),
		Creator:       user,
		Active:        true,
		Expiration:    exp,
		Type:          queries.StandardQueryType,
		EnvironmentID: envid,
		Target:        genTargetString(req.Environments, req.UUIDs, req.Hosts, req.Tags, req.Platforms),
	}
}

// Helper to verify the service is valid
func checkTargetService(service string) bool {
	if service == config.ServiceTLS {
		return true
	}
	if service == config.ServiceAdmin {
		return true
	}
	if service == config.ServiceAPI {
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
	return out.String()
}

// Helper to convert from settings values to JSON configuration
func toJSONConfigurationService(values []settings.SettingValue) *config.ServiceParameters {
	cfg := &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{},
		Admin:   &config.YAMLConfigurationAdmin{},
		Logger:  &config.YAMLConfigurationLogger{},
		Carver:  &config.YAMLConfigurationCarver{},
	}
	for _, v := range values {
		if v.Name == settings.JSONListener {
			cfg.Service.Listener = v.String
		}
		if v.Name == settings.JSONPort {
			// Convert string to int for Port assignment
			if portInt, err := strconv.Atoi(v.String); err == nil {
				cfg.Service.Port = portInt
			} else {
				cfg.Service.Port = 0 // or handle error as appropriate
			}
		}
		if v.Name == settings.JSONHost {
			cfg.Service.Host = v.String
		}
		if v.Name == settings.JSONAuth {
			cfg.Service.Auth = v.String
		}
		if v.Name == settings.JSONLogger {
			cfg.Logger.Type = v.String
		}
		if v.Name == settings.JSONCarver {
			cfg.Carver.Type = v.String
		}
		if v.Name == settings.JSONSessionKey {
			cfg.Admin.SessionKey = v.String
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

// Helper to generate the target string for on-demand queries and carves
func genTargetString(envs, uuids, hosts, tags, platforms []string) string {
	var target string
	if len(envs) > 0 {
		target += "env[" + strings.Join(envs, ",") + "];"
	}
	if len(uuids) > 0 {
		target += "uuid[" + strings.Join(uuids, ",") + "];"
	}
	if len(hosts) > 0 {
		target += "host[" + strings.Join(hosts, ",") + "];"
	}
	if len(platforms) > 0 {
		target += "platform[" + strings.Join(platforms, ",") + "];"
	}
	if len(tags) > 0 {
		target += "tag[" + strings.Join(tags, ",") + "];"
	}
	return target
}

// Helper to convert the target string to a slice of QueryTargets
func parseQueryTarget(target string) []QueryTarget {
	var targets []QueryTarget
	parts := strings.Split(target, ";")
	for _, p := range parts {
		if p != "" {
			pType := strings.SplitN(p, "[", 2)[0]
			pValue := strings.TrimSuffix(strings.SplitN(p, "[", 2)[1], "]")
			t := QueryTarget{
				Type:  pType,
				Value: pValue,
			}
			targets = append(targets, t)
		}
	}
	return targets
}

// Helper to convert the target string to a slice of CarveTargets
func parseCarveTarget(target string) []CarveTarget {
	var targets []CarveTarget
	parts := strings.Split(target, ";")
	for _, p := range parts {
		if p != "" {
			pType := strings.SplitN(p, "[", 2)[0]
			pValue := strings.TrimSuffix(strings.SplitN(p, "[", 2)[1], "]")
			t := CarveTarget{
				Type:  pType,
				Value: pValue,
			}
			targets = append(targets, t)
		}
	}
	return targets
}
