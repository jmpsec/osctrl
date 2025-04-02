package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// OctetStream for Content-Type headers
const OctetStream string = "application/octet-stream"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// TextPlain for Content-Type headers
const TextPlain string = "text/plain"

// TextPlainUTF8 for Content-Type headers, UTF charset
const TextPlainUTF8 string = TextPlain + "; charset=UTF-8"

// KeepAlive for Connection headers
const KeepAlive string = "Keep-Alive"

// ContentType for header key
const ContentType string = "Content-Type"

// ContentDescription for header key
const ContentDescription string = "Content-Description"

// ContentDisposition for header key
const ContentDisposition string = "Content-Disposition"

// ContentLength for header key
const ContentLength string = "Content-Length"

// Connection for header key
const Connection string = "Connection"

// Expires for header key
const Expires string = "Expires"

// CacheControl for header key
const CacheControl string = "Cache-Control"

// CacheControlMustRevalidate for header key
const CacheControlMustRevalidate string = "must-revalidate, post-check=0, pre-check=0"

// Pragma for header key
const Pragma string = "Pragma"

// PragmaPublic for header key
const PragmaPublic string = "public"

// ContentTransferEncoding for header key
const ContentTransferEncoding string = "Content-Transfer-Encoding"

// TransferEncodingBinary for header key
const TransferEncodingBinary string = "binary"

// UserAgent for header key
const UserAgent string = "User-Agent"

// XRealIP for header key
const XRealIP string = "X-Real-IP"

const XForwardedFor string = "X-Forwarded-For"

// Authorization for header key
const Authorization string = "Authorization"

// OsctrlUserAgent for customized User-Agent
const OsctrlUserAgent string = "osctrl-http-client/1.1"

// SendRequest - Helper function to send HTTP requests
func SendRequest(reqType, reqURL string, params io.Reader, headers map[string]string) (int, []byte, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid url: %w", err)
	}
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return 0, nil, fmt.Errorf("error loading x509 certificate pool: %w", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	req, err := http.NewRequest(reqType, reqURL, params)
	if err != nil {
		return 0, []byte("Cound not prepare request"), err
	}
	// Set custom User-Agent
	req.Header.Set(UserAgent, OsctrlUserAgent)
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Err(err).Msg("Failed to close body")
		}
	}()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}
	return resp.StatusCode, bodyBytes, nil
}

// DebugHTTP - Helper for debugging purposes and dump a full HTTP request
func DebugHTTP(r *http.Request, showBody bool) string {
	var debug string
	debug = fmt.Sprintf("%s\n", "---------------- request")
	requestDump, err := httputil.DumpRequest(r, showBody)
	if err != nil {
		log.Err(err).Msg("error while dumprequest")
	}
	debug += fmt.Sprintf("%s\n", string(requestDump))
	if !showBody {
		debug += fmt.Sprintf("%s\n", "---------------- No Body")
	}
	debug += fmt.Sprintf("%s\n", "---------------- end")
	return debug
}

// DebugHTTPDump - Helper for debugging purposes and dump a full HTTP request
func DebugHTTPDump(l *zerolog.Logger, r *http.Request, showBody bool) {
	l.Log().Msg(DebugHTTP(r, showBody))
}

// GetIP - Helper to get the IP address from a HTTP request
func GetIP(r *http.Request) string {
	realIP := r.Header.Get(XRealIP)
	if realIP != "" {
		return realIP
	}
	forwarded := r.Header.Get(XForwardedFor)
	if forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
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
			errStr := "error serializing response"
			log.Err(err).Msg(errStr)
			content = []byte(errStr)
		}
	}
	w.WriteHeader(code)
	_, _ = w.Write(content)
}

// HTTPDownload - Helper to send HTTP response with a file
func HTTPDownload(w http.ResponseWriter, description, filename string, filesize int64) {
	w.Header().Set(ContentDescription, description)
	w.Header().Set(ContentType, OctetStream)
	w.Header().Set(ContentDisposition, "attachment; filename="+filename)
	w.Header().Set(ContentTransferEncoding, TransferEncodingBinary)
	w.Header().Set(Connection, KeepAlive)
	w.Header().Set(Expires, "0")
	w.Header().Set(CacheControl, CacheControlMustRevalidate)
	w.Header().Set(Pragma, PragmaPublic)
	w.Header().Set(ContentLength, strconv.FormatInt(filesize, 10))
}
