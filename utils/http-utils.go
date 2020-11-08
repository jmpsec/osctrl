package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// TextPlain for Content-Type headers
const TextPlain string = "text/plain"

// TextPlainUTF8 for Content-Type headers, UTF charset
const TextPlainUTF8 string = TextPlain + "; charset=UTF-8"

// ContentType for header key
const ContentType string = "Content-Type"

// UserAgent for header key
const UserAgent string = "User-Agent"

// osctrlUserAgent for customized User-Agent
const osctrlUserAgent string = "osctrl-http-client/1.1"

// SendRequest - Helper function to send HTTP requests
func SendRequest(reqType, reqURL string, params io.Reader, headers map[string]string) (int, []byte, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid url: %v", err)
	}
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return 0, nil, fmt.Errorf("error loading x509 certificate pool: %v", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	req, err := http.NewRequest(reqType, reqURL, params)
	if err != nil {
		return 0, []byte("Cound not prepare request"), err
	}
	// Set custom User-Agent
	req.Header.Set(UserAgent, osctrlUserAgent)
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	//defer resp.Body.Close()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body %v", err)
		}
	}()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}

	return resp.StatusCode, bodyBytes, nil
}

// DebugHTTP - Helper for debugging purposes and dump a full HTTP request
func DebugHTTP(r *http.Request, debugCheck bool, showBody bool) string {
	var debug string
	if debugCheck {
		debug = fmt.Sprintf("%s\n", "---------------- request")
		requestDump, err := httputil.DumpRequest(r, showBody)
		if err != nil {
			log.Printf("error while dumprequest %v", err)
		}
		debug += fmt.Sprintf("%s\n", string(requestDump))
		if !showBody {
			debug += fmt.Sprintf("%s\n", "---------------- No Body")
		}
		debug += fmt.Sprintf("%s\n", "---------------- end")
	}
	return debug
}

// DebugHTTPDump - Helper for debugging purposes and dump a full HTTP request
func DebugHTTPDump(r *http.Request, debugCheck bool, showBody bool) {
	if debugCheck {
		log.Println(DebugHTTP(r, debugCheck, showBody))
	}
}

// HTTPResponse - Helper to send HTTP response
func HTTPResponse(w http.ResponseWriter, cType string, code int, data interface{}) {
	if cType != "" {
		w.Header().Set(ContentType, cType)
	}
	// Serialize if is not a []byte
	var content []byte
	if x, ok := data.([]byte); ok {
		content = x
	} else {
		var err error
		content, err = json.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("error serializing response: %v", err)
			content = []byte("error serializing response")
		}
	}
	w.WriteHeader(code)
	_, _ = w.Write(content)
}
