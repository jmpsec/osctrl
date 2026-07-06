package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestHTTPResponse(t *testing.T) {
	t.Run("json content-type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPResponse(rr, JSONApplicationUTF8, http.StatusOK, []byte("JSON Content-Type"))
		assert.Equal(t, JSONApplicationUTF8, rr.Header().Get(ContentType))
		assert.Equal(t, "JSON Content-Type", rr.Body.String())
	})
	t.Run("empty content-type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPResponse(rr, "", http.StatusOK, []byte("Empty Content-Type"))
		assert.Equal(t, "", rr.Header().Get(ContentType))
		assert.Equal(t, "Empty Content-Type", rr.Body.String())
	})
	t.Run("json body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		type DataJSON struct {
			Key1 string `json:"key1"`
			Key2 string `json:"key2"`
		}
		data := DataJSON{
			Key1: "value1",
			Key2: "value2",
		}
		HTTPResponse(rr, JSONApplication, http.StatusOK, data)
		assert.Equal(t, JSONApplication, rr.Header().Get(ContentType))
		assert.Equal(t, `{"key1":"value1","key2":"value2"}`, rr.Body.String())
	})
}

func serverMock() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/server/testing", testingMock)
	srv := httptest.NewServer(handler)
	return srv
}

func testingMock(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("the test works"))
}

func TestSendRequest(t *testing.T) {
	server := serverMock()
	defer server.Close()

	t.Run("empty url", func(t *testing.T) {
		code, _, err := SendRequest(http.MethodPost, "", nil, map[string]string{})
		assert.Error(t, err)
		assert.Equal(t, 0, code)
	})
	t.Run("invalid url", func(t *testing.T) {
		_, _, err := SendRequest(http.MethodPost, "http://whatever/notfound", nil, map[string]string{})
		assert.Error(t, err)
	})
	t.Run("url not found", func(t *testing.T) {
		code, _, err := SendRequest(http.MethodPost, server.URL+"/notfound", nil, map[string]string{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, code)
	})
	t.Run("url not found", func(t *testing.T) {
		code, body, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, map[string]string{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, []byte("the test works"), body)
	})
	t.Run("https url", func(t *testing.T) {
		_, _, err := SendRequest(http.MethodPost, "https://whatever/notfound", nil, map[string]string{})
		assert.Error(t, err)
	})
	t.Run("headers url", func(t *testing.T) {
		headers := make(map[string]string)
		headers["test"] = "aaa"
		_, _, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, headers)
		assert.NoError(t, err)
	})
}

func TestGetIP(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	// All three sub-tests run with a trusted-proxy configuration that
	// covers the test RemoteAddr (127.0.0.0/8 for httptest defaults
	// and the test addresses below). Without trust configured, GetIP
	// ignores forwarding headers — that contract is asserted in
	// TestGetIPIgnoresHeadersByDefault.
	SetTrustedProxies([]string{"127.0.0.0/8"})
	t.Run("get ip X-Real-IP header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		req.RemoteAddr = "127.0.0.1:1234" // inside trusted CIDR
		req.Header.Set(XRealIP, "1.2.3.4")
		ip := GetIP(req)
		assert.Equal(t, "1.2.3.4", ip)
	})
	t.Run("get ip X-Forwarder-For header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(XForwardedFor, "1.2.3.4")
		ip := GetIP(req)
		assert.Equal(t, "1.2.3.4", ip)
	})
	t.Run("get ip RemoteAddr", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		// No RemoteAddr set and no headers — GetIP falls back to the
		// empty value the request was built with.
		ip := GetIP(req)
		assert.Equal(t, "", ip)
	})
}

func TestHTTPDownload(t *testing.T) {
	t.Run("HTTPDownload headers", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPDownload(rr, "whatever", "file.txt", 123)
		assert.Equal(t, OctetStream, rr.Header().Get(ContentType))
		assert.Equal(t, TransferEncodingBinary, rr.Header().Get(ContentTransferEncoding))
		assert.Equal(t, KeepAlive, rr.Header().Get(Connection))
		assert.Equal(t, "0", rr.Header().Get(Expires))
		assert.Equal(t, CacheControlMustRevalidate, rr.Header().Get(CacheControl))
		assert.Equal(t, PragmaPublic, rr.Header().Get(Pragma))
	})
	t.Run("content-description", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPDownload(rr, "whatever", "file.txt", 123)
		assert.Equal(t, "whatever", rr.Header().Get(ContentDescription))
	})
	t.Run("content-disposition", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPDownload(rr, "whatever", "file.txt", 123)
		assert.Equal(t, "attachment; filename=file.txt", rr.Header().Get(ContentDisposition))
	})
	t.Run("content-length", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPDownload(rr, "whatever", "file.txt", 123)
		assert.Equal(t, "123", rr.Header().Get(ContentLength))
	})
}

// TestGetIPIgnoresHeadersByDefault — out-of-the-box GetIP MUST NOT
// consult X-Real-IP / X-Forwarded-For.
func TestGetIPIgnoresHeadersByDefault(t *testing.T) {
	SetTrustedProxies(nil) // reset
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("X-Real-IP", "99.99.99.99")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := GetIP(req); got != "203.0.113.5" {
		t.Errorf("default GetIP: got %q, want %q (forwarding headers must be ignored)", got, "203.0.113.5")
	}
}

// TestGetIPHonorsTrustedProxy — when the connecting peer is inside a
// trusted-proxy CIDR, the right-most untrusted hop from X-Forwarded-For
// becomes the result.
func TestGetIPHonorsTrustedProxy(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:12345" // trusted edge
	// `client, edge1, edge2` — edge1/edge2 are inside the trusted CIDR,
	// so the right-most-untrusted is "203.0.113.5".
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1, 10.0.0.5")
	if got := GetIP(req); got != "203.0.113.5" {
		t.Errorf("trusted XFF: got %q, want %q", got, "203.0.113.5")
	}
}

// TestGetIPUntrustedPeerIgnoresHeaders — even with trusted proxies set,
// a request coming from OUTSIDE the trusted CIDRs must ignore headers.
func TestGetIPUntrustedPeerIgnoresHeaders(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:12345" // NOT in trusted CIDR
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := GetIP(req); got != "203.0.113.5" {
		t.Errorf("untrusted peer with header: got %q, want %q", got, "203.0.113.5")
	}
}

// TestGetIPTrustedProxyIPv6 — verify IPv6 trusted-proxy match.
func TestGetIPTrustedProxyIPv6(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]string{"fd00::/8"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[fd00::1]:443"
	req.Header.Set("X-Forwarded-For", "2001:db8::1")
	if got := GetIP(req); got != "2001:db8::1" {
		t.Errorf("trusted IPv6 XFF: got %q, want %q", got, "2001:db8::1")
	}
}

// TestSetTrustedProxiesIgnoresInvalid — bad CIDRs are dropped silently
// rather than panicking; the remaining good ones still apply.
func TestSetTrustedProxiesIgnoresInvalid(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]string{"not-a-cidr", "10.0.0.0/8", "", "  "})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Real-IP", "203.0.113.5")
	if got := GetIP(req); got != "203.0.113.5" {
		t.Errorf("partial CIDR set: got %q, want %q", got, "203.0.113.5")
	}
}

// TestDebugHTTPDumpWithBody verifies the bytes-based dump helper used on
// the per-host-filtered debug path. It must serialize a request whose body
// has already been read into a []byte, include the body when showBody is
// true, surface the "No Body" marker when false, and never touch the
// original (already-consumed) request stream.
func TestDebugHTTPDumpWithBody(t *testing.T) {
	body := []byte(`{"node_key":"abc","host_identifier":"host-1"}`)

	withLogger := func(t *testing.T, showBody bool) string {
		var buf bufWriter
		logger := newZerologLogger(&buf)
		req := httptest.NewRequest("POST", "/env/enroll", nil)
		req.Header.Set("Content-Type", "application/json")
		DebugHTTPDumpWithBody(&logger, req, body, showBody)
		return buf.String()
	}

	t.Run("show body", func(t *testing.T) {
		out := withLogger(t, true)
		assert.Contains(t, out, "POST /env/enroll")
		assert.Contains(t, out, "host_identifier")
		assert.Contains(t, out, "node_key")
		assert.NotContains(t, out, "No Body")
	})

	t.Run("omit body", func(t *testing.T) {
		out := withLogger(t, false)
		assert.Contains(t, out, "POST /env/enroll")
		assert.Contains(t, out, "No Body")
		assert.NotContains(t, out, "node_key")
	})
}

// bufWriter is a minimal io.Writer backing a zerolog logger for tests.
type bufWriter struct{ b strings.Builder }

func (w *bufWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
func (w *bufWriter) String() string              { return w.b.String() }

func newZerologLogger(w *bufWriter) zerolog.Logger {
	return zerolog.New(w)
}
