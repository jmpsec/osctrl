package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/jmpsec/osctrl/version"
	"github.com/spf13/viper"
)

const (
	// APIPath for the generic API path in osctrl
	APIPath = "/api/v1"
	// APINodes for the nodes path
	APINodes = "/nodes"
	// APIQueries
	APIQueries = "/queries"
	// APICarves
	APICarves = "/carves"
	// APIUsers
	APIUSers = "/users"
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

// OsctrlAPI
type OsctrlAPI struct {
	Configuration JSONConfigurationAPI
	Client        *http.Client
	Headers       map[string]string
}

// loadAPIConfiguration to load the DB configuration file and assign to variables
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
		return config, fmt.Errorf("could not find key %s", projectName)
	}
	if err := apiRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// CreateAPI to initialize the API client and handlers
func CreateAPI(config JSONConfigurationAPI, insecure bool) *OsctrlAPI {
	var a *OsctrlAPI
	// Prepare URL
	u, err := url.Parse(config.URL)
	if err != nil {
		log.Fatalf("invalid url: %v", err)
	}
	// Define client with correct TLS settings
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			log.Fatalf("error loading x509 certificate pool: %v", err)
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

// GetGeneric - Helper function to implement generic retrieval from API
func (api *OsctrlAPI) GetGeneric(url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, body)
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
	//defer resp.Body.Close()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close body %v", err)
		}
	}()
	// Read body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("can not read response - %v", err)
	}
	// Check response code
	if resp.StatusCode != http.StatusOK {
		return bodyBytes, fmt.Errorf("HTTP Code %d", resp.StatusCode)
	}
	return bodyBytes, nil
}
