package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	// ConfigKey is the top-level JSON key the API configuration lives under
	// in the on-disk config file (osctrl-api.json). Previously read from
	// cmd/cli's projectName const; inlined here so the package stands alone.
	ConfigKey = "osctrl"
	// APIPath for the generic API path in osctrl
	APIPath = "/api/v1"
	// APINodes for the nodes path
	APINodes = "/nodes"
	// APIQueries for the queries path
	APIQueries = "/queries"
	// APICarves for the carves path
	APICarves = "/carves"
	// APIUsers for the users path
	APIUSers = "/users"
	// APIEnvironments for the environments path
	APIEnvironments = "/environments"
	// APITags for the tags path
	APITags = "/tags"
	// APILogin for the login path
	APILogin = "/login"
	// APIAuditLogs for the audit logs path
	APIAuditLogs = "/audit-logs"
	// APIStats for the fleet statistics path
	APIStats = "/stats"
	// APIOsquery for the osquery schema path
	APIOsquery = "/osquery"
	// APIChecksNoAuth for the unauthenticated checks path
	APIChecksNoAuth = "/checks-no-auth"
	// APIChecksAuth for the authenticated checks path
	APIChecksAuth = "/checks-auth"
	// JSONApplication for Content-Type headers
	JSONApplication = "application/json"
	// JSONApplicationUTF8 for Content-Type headers, UTF charset
	JSONApplicationUTF8 = JSONApplication + "; charset=UTF-8"
	// ContentType for header key
	ContentType = "Content-Type"
	// UserAgent for header key
	UserAgent = "User-Agent"
	// Authorization for header key
	Authorization = "Authorization"
	// osctrlUserAgent for customized User-Agent
	osctrlUserAgent = "osctrl-cli-http-client/" + version.OsctrlVersion
)

// JSONConfigurationAPI to hold all API configuration values
type JSONConfigurationAPI struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// OsctrlAPI to keep the struct for the API client
type OsctrlAPI struct {
	Configuration JSONConfigurationAPI
	Client        *http.Client
	Headers       map[string]string
}

// LoadConfiguration to load the API configuration file and assign to variables
func LoadConfiguration(file string) (JSONConfigurationAPI, error) {
	var config JSONConfigurationAPI
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}
	// API values
	apiRaw := viper.Sub(ConfigKey)
	if apiRaw == nil {
		return config, fmt.Errorf("JSON key %s not found in %s", ConfigKey, file)
	}
	if err := apiRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// WriteConfiguration to write the API configuration file and update values
func WriteConfiguration(file string, apiConf JSONConfigurationAPI) error {
	if apiConf.URL == "" || apiConf.Token == "" {
		return fmt.Errorf("invalid JSON values")
	}
	fileData := make(map[string]JSONConfigurationAPI)
	fileData[ConfigKey] = apiConf
	confByte, err := json.MarshalIndent(fileData, "", " ")
	if err != nil {
		return fmt.Errorf("error serializing data %w", err)
	}
	if err := os.WriteFile(file, confByte, 0644); err != nil {
		return fmt.Errorf("error writing to file %w", err)
	}
	return nil
}

// CreateAPI to initialize the API client and handlers.
//
// Returns an error rather than calling log.Fatal on bad input: as a library
// this is called by long-lived processes (and by tests) where killing the
// process on a malformed URL is not an acceptable failure mode. Callers that
// genuinely want to abort should log.Fatal on the returned error themselves.
func CreateAPI(config JSONConfigurationAPI, insecure bool) (*OsctrlAPI, error) {
	var a *OsctrlAPI
	// Prepare URL
	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid url - %w", err)
	}
	// Define client with correct TLS settings
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading x509 certificate pool - %w", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		if insecure {
			tlsCfg.InsecureSkipVerify = true
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	// Prepare authentication
	headers := make(map[string]string)
	headers[Authorization] = fmt.Sprintf("Bearer %s", config.Token)
	headers[ContentType] = JSONApplicationUTF8
	a = &OsctrlAPI{
		Configuration: config,
		Client:        client,
		Headers:       headers,
	}
	return a, nil
}

// CreateAPIWithTransport builds a client that issues its requests through rt
// instead of the network.
//
// This exists so osctrl-api can host an MCP server against its own handlers:
// the transport dispatches straight into the service's mux, so tool calls run
// the real handler chain — same authentication, same per-endpoint permission
// checks, same audit logging — without a socket. The alternative, reaching
// into the managers directly, would mean restating authorization policy that
// is deliberately non-uniform across endpoints, and any drift there
// over-grants silently.
//
// config.URL still has to parse; the transport is free to ignore its host and
// route on the path alone.
func CreateAPIWithTransport(config JSONConfigurationAPI, rt http.RoundTripper) (*OsctrlAPI, error) {
	if rt == nil {
		return nil, fmt.Errorf("nil round tripper")
	}
	if _, err := url.Parse(config.URL); err != nil {
		return nil, fmt.Errorf("invalid url - %w", err)
	}
	headers := map[string]string{
		Authorization: fmt.Sprintf("Bearer %s", config.Token),
		ContentType:   JSONApplicationUTF8,
	}
	return &OsctrlAPI{
		Configuration: config,
		Client:        &http.Client{Transport: rt},
		Headers:       headers,
	}, nil
}

// GetGeneric - Helper function to implement generic retrieval from API with a GET request
func (api *OsctrlAPI) GetGeneric(url string, body io.Reader) ([]byte, error) {
	return api.ReqGeneric(http.MethodGet, url, body)
}

// PostGeneric - Helper function to implement generic retrieval from API with a POST request
func (api *OsctrlAPI) PostGeneric(url string, body io.Reader) ([]byte, error) {
	return api.ReqGeneric(http.MethodPost, url, body)
}

// ReqGeneric - Helper function to implement generic retrieval from API with a POST request
func (api *OsctrlAPI) ReqGeneric(reqType string, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(reqType, url, body)
	if err != nil {
		return []byte{}, fmt.Errorf("NewRequest - %w", err)
	}
	// Set custom User-Agent
	req.Header.Set(UserAgent, osctrlUserAgent)
	// Prepare headers
	for key, value := range api.Headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := api.Client.Do(req)
	if err != nil {
		return []byte{}, fmt.Errorf("Client.Do - %w", err)
	}
	defer resp.Body.Close()
	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("can not read response - %w", err)
	}
	// Check response code: any 2xx is success (201 Created, 204 No
	// Content, etc.). Redirects are followed by the http client itself.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return bodyBytes, fmt.Errorf("HTTP Code %d", resp.StatusCode)
	}
	return bodyBytes, nil
}

// CheckApiAuth to check if API authentication is working
func (api *OsctrlAPI) CheckAPI() error {
	log.Debug().Msg("Preparing request to check unauthenticated API")
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIChecksNoAuth))
	rawRes, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return fmt.Errorf("error with GET request - %w", err)
	}
	log.Debug().Msgf("API unauthenticated check response: %s", string(rawRes))
	log.Debug().Msg("Preparing request to check authenticated API")
	reqURL = fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIChecksAuth))
	rawRes, err = api.GetGeneric(reqURL, nil)
	if err != nil {
		return fmt.Errorf("error with GET request - %w", err)
	}
	log.Debug().Msgf("API authenticated check response: %s", string(rawRes))
	return nil
}
