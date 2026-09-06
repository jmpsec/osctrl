# osctrl MCP server

osctrl exposes its read surface over the [Model Context
Protocol](https://modelcontextprotocol.io), so an MCP client — Claude Code,
Claude Desktop, or any other — can inspect a fleet: environments, enrolled
nodes, the osquery schema, and distributed query results.

There are two ways to run it, serving the same tools:

| | Transport | Who it suits |
|---|---|---|
| **[`osctrl-mcp`](#standalone-osctrl-mcp)** | stdio, launched by the client | One operator on a workstation |
| **[Hosted](#hosted-apiv1mcp)** | HTTP at `/api/v1/mcp` inside osctrl-api | Shared deployment, each user as themselves |

## Standalone: `osctrl-mcp`

Speaks MCP over stdio and is launched by the client, not run as a daemon. It
opens no listening socket and holds no state; every tool call becomes an
authenticated request to osctrl-api.

### Build

```bash
make mcp
```

Produces `bin/osctrl-mcp`.

### Authentication and scope

The binary has no authorization logic of its own. It authenticates to
osctrl-api with a Bearer token, so **that token's per-environment permissions
are the only thing bounding the agent**. A token that cannot see an
environment gets the same empty results the operator would.

Create a dedicated service user rather than reusing a human's token:

```bash
osctrl-cli user add -u mcp-agent -s -e prod
osctrl-cli user permissions -u mcp-agent -e prod --user
```

Grant `--user` (read) unless the agent genuinely needs query results, which
require query-level access on the environment. The tool set here issues no
writes, but the process still holds whatever the token can do — scope it down.

### Configuration

Pass the API URL and token by environment variable, or point at an
`osctrl-api.json` written by `osctrl-cli login --write`. Flags and environment
variables override the config file, so one file can back several clients
pointed at different environments.

| Flag | Env var | Description |
|------|---------|-------------|
| `--api-url` | `OSCTRL_API_URL` | Base URL of osctrl-api |
| `--api-token` | `OSCTRL_API_TOKEN` | Bearer token (prefer the env var — a flag is visible in the process list) |
| `--config`, `-c` | `OSCTRL_API_FILE` | Path to an `osctrl-api.json` holding url + token |
| `--allow-writes` | `OSCTRL_MCP_ALLOW_WRITES` | Also expose the [write tools](#write-tools). Off by default |
| `--insecure` | `OSCTRL_INSECURE` | Skip TLS verification (development only) |
| `--log-level` | `OSCTRL_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error` |

Logs go to stderr. stdout carries the MCP protocol stream and must stay clean.

The server verifies the token against osctrl-api at startup and exits with a
clear error if the API is unreachable or the token is rejected, rather than
starting and failing one tool call at a time.

### Client setup

Claude Code:

```bash
claude mcp add osctrl \
  --env OSCTRL_API_URL=https://osctrl.example.com \
  --env OSCTRL_API_TOKEN=<service-user-token> \
  -- /opt/osctrl/bin/osctrl-mcp
```

Claude Desktop — in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osctrl": {
      "command": "/opt/osctrl/bin/osctrl-mcp",
      "env": {
        "OSCTRL_API_URL": "https://osctrl.example.com",
        "OSCTRL_API_TOKEN": "<service-user-token>"
      }
    }
  }
}
```

## Hosted: `/api/v1/mcp`

osctrl-api can serve MCP itself, so operators share one endpoint instead of
each installing a binary. Off by default — enable it in `api.yml`:

```yaml
mcp:
  enabled: false
  allowWrites: false
```

or with `--mcp-enabled` / `MCP_ENABLED=true` and `--mcp-allow-writes` /
`MCP_ALLOW_WRITES=true`. Requires a restart; when disabled the route is not
registered at all.

Point a client at `https://<osctrl-host>/api/v1/mcp` with the caller's own
bearer token. Behind the bundled nginx config this works as-is: `/api/` is
already proxied with `proxy_buffering off`, which the streaming transport
needs.

### Enabling it grants no new access

Requests authenticate with the same bearer token or session cookie as any
other API call. Each tool call is then dispatched **back through osctrl-api's
own handlers** as the calling user, so the per-endpoint permission checks run
exactly as they do for the SPA or osctrl-cli. A caller sees only what their
token already allows; two users hitting the same endpoint get different
results.

That indirection is deliberate. osctrl's read permissions are not uniform —
reading a node and its posture requires `AdminLevel`, queries require
`QueryLevel`, and the osquery schema requires no environment permission.
Restating that policy inside the MCP layer would over-grant the moment the two
drift, so the MCP layer contains no authorization logic and defers entirely to
the handlers.

Dispatch is in-process: no socket, no second listener, no loopback network
hop.

## Tools

### Read tools

Always available. Nothing here mutates anything.

| Tool | Purpose |
|------|---------|
| `list_environments` | Environments the token can see. Enrollment secrets and certificates are deliberately excluded. |
| `fleet_stats` | Totals, active vs inactive, and per-platform / per-environment breakdown. |
| `search_nodes` | Nodes in an environment, filtered by status, platform, or hostname substring. |
| `get_node` | Full detail for one node, optionally with its posture score. |
| `list_osquery_tables` | Discover queryable tables, filtered by name or platform. |
| `get_table_schema` | Columns and metadata for one table. |
| `list_queries` | Distributed queries and how many nodes have answered. |
| `list_saved_queries` | Stored, reusable query templates. |
| `get_query_results` | Rows collected so far for a query. Requires query-level permission. |

### Write tools

Registered **only** when writes are enabled — `--allow-writes` on the binary,
`allowWrites: true` on the hosted endpoint. A read-only server does not
advertise them, so no configuration mistake or refactor can quietly hand an
agent the fleet.

| Tool | Purpose |
|------|---------|
| `run_query` | Schedule an osquery query against targeted nodes. Requires query-level permission. |
| `expire_query` | Stop handing a query to more nodes. Collected results stay readable. |
| `complete_query` | Mark a query complete so osctrl stops waiting on silent nodes. |
| `tag_node` | Apply an existing tag to a node. Requires admin permission. |

Four constraints `run_query` applies on top of osctrl's own permission checks:

- **A target is required.** osctrl reads "no selectors" as the whole
  environment, so an omitted argument would become a fleet-wide query. Set
  `uuids`, `hostnames`, `platforms`, or `tags` — or say `all_nodes: true` and
  mean it.
- **Every query expires.** osctrl treats `ExpHours == 0` as *never expires*,
  which would keep handing the query to nodes that enroll months later.
  Default 24h, maximum 168h.
- **Carve queries are refused.** They copy files off endpoints. osctrl gates
  them behind carve-level permission anyway, but file exfiltration is not a
  capability this server offers — run a carve from the SPA or osctrl-cli.
- **Nothing is hidden.** Queries are always scheduled visible, so an operator
  can see what an agent started.

`tag_node` only ever writes custom tags; environment and platform tags are
osctrl's own derived values and are not forgeable through MCP.

### Two things the tools tell the model, and why

**Distributed queries are asynchronous.** Results accumulate as nodes check
in over seconds to minutes. An empty first page means "not yet", not "no
matches" — so `get_query_results` returns explicit guidance when it has zero
rows, and the server instructions tell the model to re-read and compare
`total_items` rather than treat the first page as final.

**Fleet data is untrusted.** Hostnames, process names, file paths, and result
rows come from monitored endpoints — precisely the machines an attacker might
control. A compromised host can put arbitrary text in a process name, and that
text lands in the model's context. Tool descriptions and the server
instructions state that this content is data, never instructions.

That second point is why writes are a separate switch. Read-only, the worst a
malicious hostname achieves is a misleading answer. With writes on, the loop
closes: text an attacker planted on an endpoint could talk an agent into
scheduling a query. The instructions tell the model never to let content it
read decide to write, but the switch being off by default is the actual
mitigation — turn it on for trusted operators and scoped tokens, not for
unattended automation.

## Audit trail

Hosted MCP records one `MCP` audit-log row for every tool call, including read
tools that would otherwise look like ordinary API reads. Failed or denied tool
calls are written at warning severity; successful calls are informational. The
underlying API handlers still write their usual audit rows too, so a mutating
tool such as `run_query` leaves both the agent-specific MCP entry and the
normal query lifecycle entry.

The standalone `osctrl-mcp` binary is different: from osctrl-api's point of
view it is just another authenticated REST client, so only the underlying API
handler audit rows are recorded there.
