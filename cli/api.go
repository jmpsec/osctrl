package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/jmpsec/osctrl/version"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
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

// loadAPIConfiguration to load the API configuration file and assign to variables
func loadAPIConfiguration(file string) (JSONConfigurationAPI, error) {
	var config JSONConfigurationAPI
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}
	// API values
	apiRaw := viper.Sub(projectName)
	if apiRaw == nil {
		return config, fmt.Errorf("JSON key %s not found in %s", projectName, file)
	}
	if err := apiRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// writeAPIConfiguration to write the API configuration file and update values
func writeAPIConfiguration(file string, apiConf JSONConfigurationAPI) error {
	if apiConf.URL == "" || apiConf.Token == "" {
		return fmt.Errorf("invalid JSON values")
	}
	fileData := make(map[string]JSONConfigurationAPI)
	fileData[projectName] = apiConf
	confByte, err := json.MarshalIndent(fileData, "", " ")
	if err != nil {
		return fmt.Errorf("error serializing data %s", err)
	}
	if err := os.WriteFile(file, confByte, 0644); err != nil {
		return fmt.Errorf("error writing to file %s", err)
	}
	return nil
}

// CreateAPI to initialize the API client and handlers
func CreateAPI(config JSONConfigurationAPI, insecure bool) *OsctrlAPI {
	var a *OsctrlAPI
	// Prepare URL
	u, err := url.Parse(config.URL)
	if err != nil {
		log.Fatal().Msgf("invalid url: %v", err)
	}
	// Define client with correct TLS settings
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			log.Fatal().Msgf("error loading x509 certificate pool: %v", err)
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
	return a
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
		return []byte{}, fmt.Errorf("NewRequest - %v", err)
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
		return []byte{}, fmt.Errorf("Client.Do - %v", err)
	}
	defer resp.Body.Close()
	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("can not read response - %v", err)
	}
	// Check response code
	if resp.StatusCode != http.StatusOK {
		return bodyBytes, fmt.Errorf("HTTP Code %d", resp.StatusCode)
	}
	return bodyBytes, nil
}
