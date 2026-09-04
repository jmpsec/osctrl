package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	osctrlmcp "github.com/jmpsec/osctrl/pkg/mcp"
)

// mcpInternalHost is the host the in-process client addresses. Nothing
// resolves it: loopbackTransport routes on method and path only, and none of
// osctrl-api's mux patterns are host-scoped. It exists because http.Request
// requires an absolute URL.
const mcpInternalHost = "http://osctrl-api.internal"

// loopbackTransport dispatches an outbound request into an http.Handler
// instead of onto the network.
//
// This is what lets the hosted MCP server reuse osctrl-api's own handlers.
// Each MCP tool call becomes a synthetic request through the same mux a real
// client would hit, so authentication, the per-endpoint permission checks,
// and audit logging all run exactly as they do for any other caller. The MCP
// layer therefore contains no authorization logic of its own — which matters
// because osctrl's read permissions are not uniform (reading a node needs
// AdminLevel, its posture only UserLevel, queries QueryLevel), and restating
// that policy anywhere else would over-grant the moment the two drift.
type loopbackTransport struct {
	handler http.Handler
	// creds carries the inbound MCP caller's credentials onto every
	// synthetic request, so the handler chain authenticates as that user
	// rather than as the service.
	authorization string
	cookies       []*http.Cookie
	// remoteAddr and userAgent are propagated so audit-log entries and
	// rate-limit buckets attribute to the real client, not to the server
	// talking to itself.
	remoteAddr string
	userAgent  string
}

func (t *loopbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone so we never mutate the caller's request.
	out := req.Clone(req.Context())
	if t.authorization != "" {
		out.Header.Set("Authorization", t.authorization)
	}
	// Drop anything the client set and replay only the inbound cookies, so a
	// stale value cannot shadow the real session.
	out.Header.Del("Cookie")
	for _, c := range t.cookies {
		out.AddCookie(c)
	}
	if t.userAgent != "" {
		out.Header.Set("User-Agent", t.userAgent)
	}
	out.RemoteAddr = t.remoteAddr
	// The mux matches on Method + URL.Path; RequestURI must be unset on a
	// server-side request or net/http panics.
	out.RequestURI = ""

	rec := newResponseRecorder()
	t.handler.ServeHTTP(rec, out)
	return rec.result(req), nil
}

// responseRecorder is a minimal http.ResponseWriter. net/http/httptest would
// do the same job, but it is a testing package and this runs in the server.
type responseRecorder struct {
	code   int
	header http.Header
	body   bytes.Buffer
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{code: http.StatusOK, header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func (r *responseRecorder) WriteHeader(code int) { r.code = code }

func (r *responseRecorder) result(req *http.Request) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", r.code, http.StatusText(r.code)),
		StatusCode:    r.code,
		Header:        r.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(r.body.Bytes())),
		ContentLength: int64(r.body.Len()),
		Request:       req,
	}
}

// mcpHandler builds the HTTP handler serving MCP at /api/v1/mcp.
//
// apiHandler is the fully-wired API mux; tool calls are dispatched back into
// it. It is passed as an http.Handler rather than captured at construction so
// main.go can build the mux first and hand it over once.
//
// allowWrites additionally registers the mutating tools. It only decides
// whether they exist: the dispatched request still runs the handler chain, so
// a caller without QueryLevel gets a 403 from run_query exactly as they would
// from the REST endpoint.
//
// The returned handler must still be mounted behind handlerAuthCheck: that
// rejects unauthenticated callers up front, so a bad token fails once at the
// MCP boundary instead of once per tool call.
func mcpHandler(apiHandler http.Handler, version string, allowWrites bool) http.Handler {
	getServer := func(r *http.Request) *sdk.Server {
		// One client per request, bound to that request's credentials. The
		// MCP server is cheap to build and holds no state, so per-request
		// construction keeps sessions from ever sharing an identity.
		cfg := apiclient.JSONConfigurationAPI{URL: mcpInternalHost}
		client, err := apiclient.CreateAPIWithTransport(cfg, &loopbackTransport{
			handler:       apiHandler,
			authorization: r.Header.Get("Authorization"),
			cookies:       r.Cookies(),
			remoteAddr:    r.RemoteAddr,
			userAgent:     r.Header.Get("User-Agent"),
		})
		if err != nil {
			// CreateAPIWithTransport only fails on a malformed constant URL
			// or a nil transport, neither of which is reachable here.
			return nil
		}
		if allowWrites {
			return osctrlmcp.NewServer(client, version, osctrlmcp.WithWrites(client))
		}
		return osctrlmcp.NewServer(client, version)
	}
	return sdk.NewStreamableHTTPHandler(getServer, nil)
}
