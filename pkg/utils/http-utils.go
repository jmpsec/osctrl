package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

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

// AcceptsJSON reports whether the request's Accept header signals JSON.
// Used by the auth middleware to choose between 401 JSON (for SPA/XHR
// clients) and 302 redirect (for browser navigation).
func AcceptsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(strings.ToLower(accept), "application/json")
}

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

// trustedProxies is the global set of CIDRs whose X-Real-IP /
// X-Forwarded-For headers GetIP is allowed to honor. When empty (the
// safe default), GetIP returns the connection's RemoteAddr IP verbatim
// and ignores any forwarding headers — preventing an anonymous internet
// attacker from rotating headers to defeat rate-limits or poison the
// audit log. Operators wire trusted proxies at startup via
// SetTrustedProxies; once set, GetIP only consults forwarding headers
// when the connecting peer falls inside one of the configured CIDRs.
var (
	trustedProxiesMu sync.RWMutex
	trustedProxies   []*net.IPNet
)

// SetTrustedProxies configures the CIDR allowlist for forwarding-header
// trust. Pass an empty slice (or call with no args) to revert to the
// safe-by-default "ignore forwarding headers" posture. Each CIDR string
// must parse via net.ParseCIDR; invalid entries are logged and skipped.
func SetTrustedProxies(cidrs []string) {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Warn().Str("cidr", c).Err(err).Msg("trusted-proxies: invalid CIDR, skipping")
			continue
		}
		parsed = append(parsed, n)
	}
	trustedProxiesMu.Lock()
	trustedProxies = parsed
	trustedProxiesMu.Unlock()
}

// isFromTrustedProxy reports whether the connecting peer (host portion
// of r.RemoteAddr) sits inside any configured trusted-proxy CIDR.
func isFromTrustedProxy(r *http.Request) bool {
	trustedProxiesMu.RLock()
	tps := trustedProxies
	trustedProxiesMu.RUnlock()
	if len(tps) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range tps {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP returns the connecting peer's IP (no port). Falls back to
// RemoteAddr-as-is when SplitHostPort fails (rare; some net/http test
// machinery omits the port).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// GetIP returns the client IP for r. When trusted-proxies are configured
// AND r.RemoteAddr's IP is inside one of them, the right-most untrusted
// hop from X-Forwarded-For (or X-Real-IP) is used (per RFC 7239 §5.2 the
// right-most-untrusted is the IP the trusted edge actually saw connect).
// Otherwise the forwarding headers are ignored and the connection's
// RemoteAddr IP is returned.
func GetIP(r *http.Request) string {
	if !isFromTrustedProxy(r) {
		// Default safe path: never trust forwarding headers.
		return remoteIP(r)
	}
	// Trusted-proxy path. Prefer X-Forwarded-For (a comma-list of hops:
	// `client, proxy1, proxy2`). Walk right-to-left and return the
	// first IP that's NOT itself inside a trusted-proxy CIDR.
	if xff := r.Header.Get(XForwardedFor); xff != "" {
		hops := strings.Split(xff, ",")
		trustedProxiesMu.RLock()
		tps := trustedProxies
		trustedProxiesMu.RUnlock()
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			ip := net.ParseIP(hop)
			if ip == nil {
				continue
			}
			isProxy := false
			for _, n := range tps {
				if n.Contains(ip) {
					isProxy = true
					break
				}
			}
			if !isProxy {
				return hop
			}
		}
	}
	// Fall back to X-Real-IP (set by single-hop edges like nginx with
	// `proxy_set_header X-Real-IP $remote_addr;`).
	if rip := strings.TrimSpace(r.Header.Get(XRealIP)); rip != "" {
		return rip
	}
	// Last resort: the trusted proxy's own address.
	return remoteIP(r)
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
