// Package mcp exposes osctrl's read surface to Model Context Protocol
// clients, so an LLM agent can inspect a fleet — nodes, environments,
// query results, and the osquery schema — without being handed the raw
// REST API.
//
// The tool set here is deliberately read-only. Nothing in this package
// schedules a query, mutates a node, or touches user or service
// configuration; write tools are gated behind a separate opt-in and are
// not part of this package yet.
//
// # Authorization
//
// This package performs no authorization of its own. Every call goes
// through a Backend, and the only Backend today is *apiclient.OsctrlAPI
// talking to osctrl-api with a user's Bearer token — so osctrl-api's
// existing per-environment RBAC is what actually constrains the agent.
// A token that cannot see an environment gets the same empty results an
// operator with that token would get. Give the MCP server a service user
// scoped to exactly what the agent should read.
//
// # Untrusted content
//
// Hostnames, process names, file paths, and query result rows originate
// on monitored endpoints, which are precisely the machines an attacker
// might control. Everything this package returns is data, never
// instructions. Tool descriptions say so explicitly, because that text is
// what the model actually reads.
package mcp

import (
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// Backend is the slice of osctrl the MCP tools need.
//
// Narrow on purpose. *apiclient.OsctrlAPI satisfies it as-is, and keeping
// the surface this small means the tools can be tested against a fake
// without an HTTP server — and lets a future in-process implementation
// (MCP mounted inside osctrl-api) skip the network hop without touching
// any tool code.
type Backend interface {
	GetEnvironments() ([]environments.TLSEnvironment, error)
	GetStats() (apiclient.StatsResponse, error)

	GetNodes(env, target string) ([]nodes.OsqueryNode, error)
	GetNode(env, identifier string) (nodes.OsqueryNode, error)
	GetNodePosture(env, uuid string) ([]posture.NodePosture, error)
	GetNodePostureScore(env, uuid string) (posture.PostureScore, error)

	GetOsqueryTables() ([]types.OsqueryTable, error)

	GetQueries(target, env string) ([]queries.DistributedQuery, error)
	GetQueryResults(env, name string, page, pageSize int) (types.QueryResultsResponse, error)
	GetSavedQueries(env string) ([]types.SavedQueryView, error)
}

// Compile-time proof that the HTTP client is a valid Backend. If a method
// signature drifts in pkg/apiclient, this breaks here rather than at the
// call site in cmd/osctrl-mcp.
var _ Backend = (*apiclient.OsctrlAPI)(nil)

// WriteBackend is the mutating slice of osctrl, kept separate from Backend so
// the write tools cannot be registered by accident: NewServer takes a Backend
// and stays read-only unless a caller also passes WithWrites.
//
// As with Backend, nothing here performs authorization. RunQuery needs
// QueryLevel on the environment (and CarveLevel too if the SQL touches
// carves); TagNode needs AdminLevel. Those checks belong to osctrl-api.
type WriteBackend interface {
	RunQuery(env, query string, uuids, hosts, platforms, tags []string, hidden bool, exp int) (types.ApiQueriesResponse, error)
	ExpireQuery(env, name string) (types.ApiGenericResponse, error)
	CompleteQuery(env, name string) (types.ApiGenericResponse, error)
	TagNode(env, identifier, tag string, tagType uint, custom string) error
}

var _ WriteBackend = (*apiclient.OsctrlAPI)(nil)
