package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	osctrlmcp "github.com/jmpsec/osctrl/pkg/mcp"
)

// maxAuditedArgsBytes bounds how much of a tool call's arguments the audit
// middleware records. Tool inputs are small scalars and short lists by
// construction (see pkg/mcp's tool schemas); this only guards against a
// pathological or malicious client sending an oversized arguments blob and
// bloating the audit_logs table.
const maxAuditedArgsBytes = 500

// mcpAuditLog is the one audit-log capability the MCP boundary needs.
// Narrowed to a single method — matching the Backend/WriteBackend pattern in
// pkg/mcp — so tests can fake it without a database.
type mcpAuditLog interface {
	MCPToolCall(username, tool, args, ip string, envID uint, failed bool)
}

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
//
// auditLog receives one entry per tool call, tagged with auditlog.LogTypeMCP
// so an operator can filter agent activity out of the far larger volume of
// SPA/CLI-driven entries, which carry no origin marker at all. This is only
// possible here, at the hosted boundary: osctrl-api itself is dispatching
// the call, so it has first-hand knowledge the request came from MCP. The
// standalone stdio binary (cmd/mcp) is, from the server's point of view,
// just another authenticated HTTP client — indistinguishable from
// osctrl-cli — and its calls are audited the same way any REST client's
// would be, with no special tagging.
func mcpHandler(apiHandler http.Handler, version string, allowWrites bool, auditLog mcpAuditLog) http.Handler {
	getServer := func(r *http.Request) *sdk.Server {
		// Captured once per session (getServer runs at session creation, not
		// per tool call — see mcp.NewStreamableHTTPHandler), same lifetime
		// as the credentials loopbackTransport binds below.
		username := mcpCallerUsername(r)
		ip := strings.Split(r.RemoteAddr, ":")[0]

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
		var srv *sdk.Server
		if allowWrites {
			srv = osctrlmcp.NewServer(client, version, osctrlmcp.WithWrites(client))
		} else {
			srv = osctrlmcp.NewServer(client, version)
		}
		srv.AddReceivingMiddleware(auditToolCalls(auditLog, username, ip))
		return srv
	}
	return sdk.NewStreamableHTTPHandler(getServer, nil)
}

// mcpCallerUsername reads the username handlerAuthCheck already resolved and
// stashed on the request context before mcpHandler ever runs. Re-deriving it
// here (rather than re-parsing the token) keeps this file agreeing with the
// rest of cmd/api about who the caller is, with no second source of truth.
func mcpCallerUsername(r *http.Request) string {
	cv, ok := r.Context().Value(handlers.ContextKey(contextAPI)).(handlers.ContextValue)
	if !ok {
		return ""
	}
	return cv["user"]
}

// auditToolCalls records one auditLog.MCPToolCall entry per "tools/call"
// request on this session — every read tool included, matching the existing
// convention of auditing GET-style views (see NodeAction's "viewed all
// nodes" and friends) rather than treating audit volume as a reason to skip
// reads. It never blocks or fails a tool call: audit failures only log a
// warning inside MCPToolCall itself.
func auditToolCalls(auditLog mcpAuditLog, username, ip string) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			result, err := next(ctx, method, req)
			if method != "tools/call" {
				return result, err
			}

			tool, args := toolCallDetails(req)
			failed := err != nil
			// A tool error is reported in-band (IsError on the result, no Go
			// error) so the model can see and self-correct — see
			// CallToolResult.IsError. That still counts as "failed" for the
			// audit trail: a denied run_query is exactly what an operator
			// wants to be able to find.
			if ctr, ok := result.(*sdk.CallToolResult); ok && ctr.IsError {
				failed = true
			}
			auditLog.MCPToolCall(username, tool, args, ip, auditlog.NoEnvironment, failed)
			return result, err
		}
	}
}

// toolCallDetails extracts the tool name and a size-bounded JSON rendering
// of its arguments from a tools/call request. The concrete parameter type
// varies by SDK dispatch phase (CallToolParamsRaw server-side,
// CallToolParams on the wire-shaped path); both are handled so this never
// depends on an SDK internal staying the same across versions any more than
// necessary. An unrecognized type degrades to an empty summary rather than
// panicking — a middleware must never be the reason a tool call fails.
func toolCallDetails(req sdk.Request) (tool, args string) {
	switch p := req.GetParams().(type) {
	case *sdk.CallToolParamsRaw:
		return p.Name, truncate(string(p.Arguments), maxAuditedArgsBytes)
	case *sdk.CallToolParams:
		b, err := json.Marshal(p.Arguments)
		if err != nil {
			return p.Name, ""
		}
		return p.Name, truncate(string(b), maxAuditedArgsBytes)
	default:
		return "unknown", ""
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
