# Architecture

## Overview

`osctrl` is a multi-service Go backend for managing `osquery` fleets. The runtime is split into two long-lived HTTP services under `cmd/`:

- `cmd/tls`: `osctrl-tls`, the osquery-facing remote API endpoint.
- `cmd/api`: `osctrl-api`, the REST API used by the React operator frontend, CLI, automation, and hosted MCP.

`cmd/cli` builds `osctrl-cli`, which is an operator tool and bootstrap client rather than a long-lived service.

`cmd/mcp` builds `osctrl-mcp`, a stateless Model Context Protocol server launched by an MCP client over stdio. It does not connect to the database directly: every tool call uses an API bearer token to call `osctrl-api`. The same tools can also be hosted inside `osctrl-api` at `/api/v1/mcp` using HTTP transport. See [`MCP.md`](./MCP.md) for the complete client and tool reference.

Both HTTP services share the same data model and business logic in `pkg/*`. PostgreSQL, MySQL, and SQLite are supported through GORM in [`pkg/backend`](./pkg/backend/backend.go). Redis is a required runtime dependency for both services: it backs shared environment and settings caches, distributed-query dispatch hints, node activity rollups, and alert state. Direct database reads remain the primary path for most CRUD and list operations, while node-key caching, compiled alert rules, and live log exporters retain process-local state.

The system is UUID-scoped in two important ways:

- TLS agent routes require `TLSEnvironment.UUID` in the path, for example `POST /{env}/enroll`. Operator API routes generally accept an environment name or UUID.
- Nodes have a stable `OsqueryNode.UUID`; API detail lookups can accept a node UUID, hostname, or local name, while mutations and osquery protocol state generally use the UUID or `node_key`.

Operationally, agent identity uses stable UUIDs and `node_key`, management routes mix UUIDs with human-readable names, and internal joins and relationships still use numeric database IDs (`EnvironmentID`, `NodeID`, `UserID`).

## Runtime Topology

```text
osquery agents --------------------> osctrl-tls ---+
                                                    |
browser ---> React frontend --------> osctrl-api ---+--> PostgreSQL/MySQL/SQLite
automation / osctrl-cli ------------> osctrl-api ---+
MCP client ---> osctrl-mcp --REST---> osctrl-api ---+
MCP client --------HTTP MCP---------> osctrl-api ---+
                                                    |
osctrl-tls / osctrl-api ----------------------------+--> Redis
```

Typical dev/proxy topology from [`docker-compose-dev.yml`](./docker-compose-dev.yml):

```text
nginx :8443 -> osquery remote API -> osctrl-tls :9000
nginx :8444 -> React frontend
                   `- /api -> osctrl-api :9002
```

Main runtime components:

- `osctrl-tls`: enrollment, config distribution, log ingestion, distributed query read/write, file carving, optional `osctrld` endpoints, optional Prometheus metrics.
- React frontend: browser-based operator UI served by nginx and backed by `osctrl-api`.
- `osctrl-api`: REST API for the frontend, integrations, CLI automation, and optional hosted MCP; JWT authentication is the secure default.
- `osctrl-mcp`: standalone stdio adapter from MCP tool calls to authenticated `osctrl-api` requests; it has no database connection or listening socket.
- Hosted MCP: optional HTTP transport inside `osctrl-api`, disabled by default and using the caller's existing API identity.
- Database: source of truth for fleet inventory, users and permissions, distributed work, console/file-explorer sessions, configuration, posture, alerts, and audit records. Osquery logs are database-backed only when a DB log sink is configured.
- Redis: shared environment/settings caching, empty-query dispatch caching, node activity rollups, alert cooldown/deduplication, and inactive-node transition state.
- Process-local state: node-key cache, immutable alert-rule snapshots, live log exporters and counters, request rate-limit buckets, and background workers.

## Repository Areas

- `cmd/tls`, `cmd/api`, `cmd/cli`, `cmd/mcp`: service and client entrypoints.
- `cmd/*/handlers`: HTTP handlers and service-specific request logic.
- `pkg/backend`: GORM database bootstrap and DSN handling.
- `pkg/cache`: Redis bootstrap, typed Redis JSON caching, process-local generic caching, and cache metrics.
- `pkg/activity`, `pkg/alerts`: Redis-backed node activity and rule-driven alert evaluation/dispatch.
- `pkg/auth`, `pkg/authproviders`, `pkg/mfa`: OIDC/SAML providers, federated-login state, TOTP, WebAuthn, and recovery codes.
- `pkg/console`, `pkg/fileexplorer`: interactive workflows implemented through distributed queries.
- `pkg/environments`: environment model, enrollment/config path metadata, package/script metadata.
- `pkg/nodes`: node registry, lookup, archive, metadata updates.
- `pkg/queries`: distributed query definitions, targets, node-query state, saved queries.
- `pkg/carves`: file carving metadata and storage backends (`db`, `local`, `s3`).
- `pkg/logging`: TLS log pipeline, sink implementations (`db`, `file`, `stdout`, `graylog`, `splunk`, `logstash`, `kinesis`, `s3`, `kafka`, `elastic`), and DB/S3 readers.
- `pkg/logsinks`: persisted global and per-environment log-sink configuration.
- `pkg/users`: admin users, JWT handling, permissions.
- `pkg/settings`: runtime settings persisted in `setting_values`.
- `pkg/tags`: tags and node-tag associations.
- `pkg/auditlog`: audit/event records for API actions, TLS security/service events, and hosted MCP activity.
- `pkg/mcp`: MCP server registration, tool schemas, read tools, and separately enabled write tools shared by standalone and hosted transports.
- `pkg/apiclient`: authenticated REST client used by `osctrl-cli` and standalone `osctrl-mcp`.
- `pkg/posture`: optional posture ingestion, checks, and scoring.
- `pkg/serviceconfig`, `pkg/servicecommands`: persisted service sections and DB-mediated control requests between API and TLS processes.
- `deploy`: Docker, nginx, systemd, osquery assets, sample YAML configs.
- `tools`: helper scripts, Bruno collections, release tooling.

## Startup Flow

Both long-lived backend services follow the same pattern in their `main.go`:

1. Load flags and optionally replace them with YAML config using `viper`.
2. Initialize structured logging.
3. Connect to the database with retry (`backend.CreateDBManager`).
4. Connect to Redis with retry (`cache.CreateRedisManager`).
5. Construct core and enabled feature managers; their constructors run GORM `AutoMigrate` for owned tables.
6. Seed scalar settings and structured service configuration, then resolve database-backed configuration overrides.
7. Build caches, readers/exporters, handlers, and background workers.
8. Register routes on `http.NewServeMux()`.
9. Start HTTP or HTTPS depending on `tls.termination`.

Service-specific additions:

- `osctrl-tls` wires Redis-backed environment/settings/query-dispatch caches, node activity batching, node metadata batching, persisted log sinks, service-command polling, and optional DB-health, posture, alerting, and Prometheus components.
- `osctrl-api` wires the shared environment/query caches and activity reader; initializes audit, MFA, console, file-explorer, service-config, log-sink, and auth-provider managers; and conditionally registers posture, alerting, service-management, federated-auth, and hosted-MCP routes.

The standalone `osctrl-mcp` process has a smaller startup flow:

1. Resolve the API URL and bearer token from flags, environment variables, or an `osctrl-api.json` file.
2. Validate the API URL and token with `osctrl-api`.
3. Register read-only tools, plus write tools only when `--allow-writes` is set.
4. Serve MCP over stdio, keeping logs on stderr so stdout remains a clean protocol stream.

When hosted MCP is enabled, `osctrl-api` registers `/api/v1/mcp` and serves the same tool definitions over HTTP. Tool calls are dispatched in-process through the existing API handlers rather than bypassing their authorization checks.

## Routing And Middleware

Routing is plain `net/http` with Go 1.22 style patterns on `http.NewServeMux()`. There is no external router dependency in the runtime path.

Representative routes (some are feature-gated):

- TLS routes in [`cmd/tls/main.go`](./cmd/tls/main.go):
  - `POST /{env}/enroll`
  - `POST /{env}/config`
  - `POST /{env}/log`
  - `POST /{env}/read`
  - `POST /{env}/write`
  - `POST /{env}/init`
  - `POST /{env}/block`
- API routes in [`cmd/api/main.go`](./cmd/api/main.go):
  - `POST /api/v1/login`
  - `POST /api/v1/login/{env}`
  - `GET /api/v1/nodes/{env}/all`
  - `POST /api/v1/queries/{env}`
  - `GET /api/v1/settings/{service}/{env}`
  - `/api/v1/mcp` when `mcp.enabled` is true

Request controls are composed at route registration:

- `cmd/api/auth.go`: `handlerAuthCheck(...)` accepts a bearer JWT or the SPA's JWT cookie, verifies it against the user's currently stored token, enforces CSRF on cookie-authenticated mutations, and attaches the username to request context.
- Login, pre-auth discovery, service-config apply, and TLS enrollment have configurable in-memory per-IP rate limits.
- Forwarded client IP headers are ignored unless the peer matches configured trusted-proxy CIDRs.
- `cmd/tls/handlers/handlers.go`: `PrometheusMiddleware(...)` records request duration/status for enabled osquery-facing endpoints; handlers also apply endpoint-specific body-size caps.

There is no global middleware chain or declarative authorization policy. Authentication wrappers, rate limits, feature gates, and permission checks are attached explicitly to routes and handlers.

## Authentication / Session Model

### API

- Auth modes: `none` or `jwt` (`config.AuthNone`, `config.AuthJWT`).
- `auth=none` requires the explicit `OSCTRL_INSECURE_NO_AUTH=1` opt-in and treats every request as a full administrator; it is intended only for local development.
- Password login is available at `POST /api/v1/login` and the compatibility route `POST /api/v1/login/{env}`. The latter additionally requires admin access to that environment.
- JWT creation and verification live in [`pkg/users/users.go`](./pkg/users/users.go).
- JWT claims are minimal: username plus standard registered claims.
- The same JWT is returned for bearer clients and stored in the Secure, HttpOnly `osctrl_token` cookie for the SPA. Every request also compares it with `admin_users.api_token`, so logout, refresh, or a later login revokes the previous token. There is one active token per user rather than a separate web-session table.
- Cookie-authenticated mutations use a double-submit `osctrl_csrf` token that is also checked against the value stored on the user row. Bearer-only clients are exempt from CSRF checks.
- Password users can enroll TOTP, WebAuthn credentials, and recovery codes. MFA can be required deployment-wide; service users and federated logins follow separate policies.
- OIDC and SAML login providers can be built from persisted `auth_providers` rows. Provider login state is signed, audience-bound, short-lived, and stored in Secure cookies; optional JIT user provisioning and group gates are enforced by the provider layer. Current activation limitations are documented below and in [docs/auth-providers.md](./docs/auth-providers.md).

### MCP

- Standalone `osctrl-mcp` authenticates to `osctrl-api` with its configured bearer token. The token's per-environment permissions bound every tool call.
- Hosted MCP accepts the same bearer-token or session identity as the surrounding API and dispatches calls through existing handlers, preserving endpoint-specific permission checks.
- Read tools are always registered. Query and tag mutations are registered only when the independent MCP write switch is enabled; normal query/admin permissions still apply afterward.
- Hosted tool calls create MCP audit records. Standalone calls appear as ordinary authenticated REST operations in the API audit trail.

### Authorization

- Users live in `admin_users`.
- Per-environment access lives in `user_permissions`.
- The user manager's `CheckPermissions(...)` method grants access by environment UUID/string plus level (`user`, `query`, `carve`, `admin`).
- Full admins bypass per-environment checks.

## Settings Subsystem

Scalar runtime settings are database-backed and service-scoped.

- Model: `pkg/settings.SettingValue`
- Table: `setting_values`
- Key fields:
  - `Name`
  - `Service` (`tls`, `api`)
  - `EnvironmentID`
  - `Type`
  - `String` / `Boolean` / `Integer`

Patterns in the current implementation:

- Each service seeds default scalar settings on startup:
  - TLS: `accelerated_seconds`, `oneliner_expiration`
  - API: `service_metrics`, `refresh_settings`, `inactive_hours`
- `pkg/serviceconfig` separately stores structured JSON sections in `service_configs`, resolves database overrides at startup, and records each process's YAML path/writability in `config_file_statuses`.
- Sensitive or connection-bearing sections are read-only through the service-config API. Log sinks and federated auth providers have dedicated tables and APIs.
- `osctrl-tls` reads its settings map through `RedisSettingsCache`; the normal cache TTL is five minutes unless a TLS-scoped `refresh_settings` row is present. The API reads scalar settings directly from the database.

## Logs / Activity Data

There are three different operational data streams:

### osquery runtime data

Handled by `pkg/logging`.

- `osctrl-tls` receives logs on `POST /{env}/log`.
- `LoggerTLS.ProcessLogs(...)` parses metadata and dispatches to the configured sink.
- Database sink models in [`pkg/logging/db.go`](./pkg/logging/db.go):
  - `OsqueryStatusData` -> `osquery_status_data`
  - `OsqueryResultData` -> `osquery_result_data`
  - `OsqueryQueryData` -> `osquery_query_data`

These records are keyed primarily by node UUID and environment name.

### node activity rollups

Handled by `pkg/activity`.

- `osctrl-tls` batches enroll/config/log/query endpoint counters into compact hourly Redis buckets.
- Per-node and per-environment series, plus status-error rankings, are read by API dashboard endpoints.
- Keys expire after eight days; API reads are capped to the seven-day reporting window.

### audit activity

Handled by `pkg/auditlog`.

- Model: `AuditLog`
- GORM table: `audit_logs`
- Created from API and hosted MCP actions such as login, node/query/carve actions, settings changes, and MCP tool calls. TLS also records failed enrollment and consumed service-control events.

## Request Flow

### osquery enrollment and steady-state flow

```text
osquery agent
  -> POST /{env}/enroll
  -> EnvCache.GetByUUID(env UUID)
  -> validate enroll secret
  -> create/update OsqueryNode
  -> return node_key

agent with node_key
  -> POST /{env}/config | /log | /read | /write | /init | /block
  -> look up node by node_key
  -> update node metadata / read env config / ingest logs / read queries / store query results / store carve blocks
```

Concrete example for config:

1. `ConfigHandler` reads `{env}` from the route.
2. It validates that `{env}` is a UUID.
3. It loads the environment via `EnvCache.GetByUUID(...)`.
4. It reads the request body into `types.ConfigRequest`.
5. It resolves the node by `node_key`.
6. It queues a `lastSeenUpdate` in the batch writer.
7. It returns `env.Configuration` as the osquery config payload.

### operator/API flow

```text
browser -> React frontend -> osctrl-api
CLI / automation ---------> osctrl-api
  -> JWT auth wrapper
  -> handler in cmd/api/handlers
  -> manager in pkg/*
  -> GORM persistence
```

Examples:

- API node detail: `GET /api/v1/nodes/{env}/node/{node}` -> JWT auth -> admin-level environment permission -> node lookup -> JSON response.
- API query run: `POST /api/v1/queries/{env}` -> JWT auth -> create `distributed_queries` row plus `distributed_query_targets` and `node_queries`.

### MCP flow

```text
standalone MCP client
  -> stdio -> osctrl-mcp
  -> bearer-authenticated REST request -> osctrl-api handler
  -> existing environment permission check
  -> pkg/* manager -> database/cache

hosted MCP client
  -> HTTP /api/v1/mcp -> osctrl-api MCP transport
  -> in-process dispatch -> existing osctrl-api handler
  -> existing environment permission check
  -> pkg/* manager -> database/cache
```

The standalone process holds the configured API token in memory but stores no fleet state. Values returned from nodes, including hostnames and query rows, are treated as untrusted model context. Write tools are disabled by default to keep endpoint-controlled text from closing a read-to-write loop without an explicit operator decision.

## Persistence Model

Persistence is mostly direct GORM `AutoMigrate` plus CRUD. There is no separate migration system in the current codebase.

Primary database models/tables:

Feature-owned tables are migrated only when their manager is initialized. In particular, posture and alert tables require those features to be enabled; osquery log tables require a DB logger.

- Environments:
  - `pkg/environments.TLSEnvironment` -> `tls_environments`
  - `pkg/environments.EnvironmentPackage` -> `environment_packages`
- Nodes:
  - `pkg/nodes.OsqueryNode` -> `osquery_nodes`
  - `pkg/nodes.ArchiveOsqueryNode` -> `archive_osquery_nodes`
- Users and auth:
  - `pkg/users.AdminUser` -> `admin_users`
  - `pkg/users.UserPermission` -> `user_permissions`
  - `pkg/authproviders.AuthProvider` -> `auth_providers`
  - `pkg/mfa.*` -> `user_mfa_totp`, `user_mfa_recovery_codes`, `user_mfa_credentials`, `user_mfa_challenges`
- Queries:
  - `pkg/queries.DistributedQuery` -> `distributed_queries`
  - `pkg/queries.NodeQuery` -> `node_queries`
  - `pkg/queries.DistributedQueryTarget` -> `distributed_query_targets`
  - `pkg/queries.SavedQuery` -> `saved_queries`
- Carves:
  - `pkg/carves.CarvedFile` -> `carved_files`
  - `pkg/carves.CarvedBlock` -> `carved_blocks`
- Interactive workflows:
  - `pkg/console.Session` / `Command` -> `console_sessions`, `console_commands`
  - `pkg/fileexplorer.Session` / `Request` -> `file_explorer_sessions`, `file_explorer_requests`
- Tags:
  - `pkg/tags.AdminTag` -> `admin_tags`
  - `pkg/tags.TaggedNode` -> `tagged_nodes`
- Settings:
  - `pkg/settings.SettingValue` -> `setting_values`
  - `pkg/serviceconfig.ServiceConfig` -> `service_configs`
  - `pkg/serviceconfig.ConfigFileStatus` -> `config_file_statuses`
  - `pkg/servicecommands.ServiceCommand` -> `service_commands`
  - `pkg/logsinks.LogSink` -> `log_sinks`
- Posture:
  - `pkg/posture.NodePosture` -> `node_posture`
  - `pkg/posture.PostureCheck` -> `posture_checks`
- Alerts:
  - `pkg/alerts.AlertRule` -> `alert_rules`
  - `pkg/alerts.AlertChannel` -> `alert_channels`
  - `pkg/alerts.AlertHistory` -> `alert_history`
- Logs:
  - `pkg/logging.OsqueryStatusData` -> `osquery_status_data`
  - `pkg/logging.OsqueryResultData` -> `osquery_result_data`
  - `pkg/logging.OsqueryQueryData` -> `osquery_query_data`
- Audit:
  - `pkg/auditlog.AuditLog` -> `audit_logs`

Redis-only state such as activity rollups, query-dispatch hints, and alert cooldown/inactive markers is not represented in these tables. Important relationships are implemented through indexed ID/UUID fields and application code rather than database foreign-key constraints.

## Deployment Notes

- Dev stack: [`docker-compose-dev.yml`](./docker-compose-dev.yml) runs nginx, the React frontend, `osctrl-tls`, `osctrl-api`, Postgres, Redis, CLI bootstrap, and sample osquery clients.
- Production-oriented assets live under `deploy/`:
  - sample YAML configs in `deploy/config/*.yml`
  - systemd unit template in `deploy/config/systemd.service`
  - nginx config in `deploy/nginx/`
  - Dockerfiles in `deploy/cicd/docker/` and `deploy/docker/dockerfiles/`
- Tagged releases publish direct `osctrl-mcp` binaries for Linux, macOS, and Windows on amd64 and arm64. Branch CI retains snapshot MCP binaries as workflow artifacts. MCP is not currently shipped as a container or native OS package.
- GoReleaser creates DEB and RPM packages for `osctrl-tls`, `osctrl-api`, and `osctrl-cli`.
  - TLS/API binaries install under `/opt/osctrl/bin`.
  - Live configuration and `.yml.example` files install under `/opt/osctrl/config` with mode `0640` and `config|noreplace` upgrade semantics.
  - TLS/API systemd units are rendered from `deploy/config/systemd.service` and installed under `/usr/lib/systemd/system`.
  - Package hooks create the shared unprivileged `osctrl` account, reload systemd, and stop/disable the relevant service on removal without deleting the shared account.
- Packages do not start services automatically because the samples contain deployment-specific credentials and an unset API JWT secret. Configure them first, then use `systemctl enable --now osctrl-tls.service` and `systemctl enable --now osctrl-api.service`.
- TLS termination can happen in the service itself (`tls.termination=true`) or at nginx.
- `osctrl-api` commonly runs with `service.auth=jwt`.
- `osctrl-tls` commonly runs with `service.auth=none`; osquery trust is based on per-environment secrets and `node_key` exchange rather than user auth.
- The CLI is used in the dev stack to create the initial environment/admin user.

## Known Constraints

- Schema evolution uses GORM `AutoMigrate` from manager constructors. There is no ordered, versioned migration framework or explicit rollback path, so model changes run during service startup.
- A configured SQL backend (PostgreSQL, MySQL, or SQLite) and Redis are startup dependencies for both HTTP services. Redis failures are not treated as an optional cache outage.
- DB degraded mode is opt-in and only helps paths whose required environment/settings entries are already warm in Redis. It does not make general API CRUD or other database-backed operations available; continued TLS ingestion also depends on warm node state and the configured log sink.
- The node-key cache, alert rule snapshots, live exporter state, and rate-limit buckets are process-local. Several refresh, retention, stats, inactive-node, and service-command workers run inside their owning service process; there is no general leader-election layer for horizontally replicated services.
- The API and TLS services share tables and packages directly. API config restart is signaled in-process; restart/reload/persist requests targeting TLS use the database-backed `service_commands` queue rather than a service-to-service API.
- Database-backed auth-provider activation is incomplete. Provider discovery advertises ID-scoped login URLs, but the API registers only the legacy YAML-gated OIDC/SAML public routes. In addition, `POST /api/v1/auth-providers/apply` targets `osctrl-tls` with `reload-auth-providers`; the TLS watcher does not handle that action and the API has no command consumer. Use YAML/flag providers for working federated login until the ID-scoped routes and API-side reload path are completed.
- Authentication is centralized in route wrappers, but environment authorization remains a handler-by-handler `CheckPermissions` responsibility. There is no declarative policy layer to prevent permission drift between related endpoints.
- Scalar-setting changes do not explicitly invalidate `osctrl-tls`'s Redis settings entry, so TLS can observe them only after its cache TTL. Environment mutations do invalidate the shared Redis environment cache.
- Retention is feature-specific: activity rollups expire in Redis and alert history is pruned daily when alerting is enabled, but osquery log rows, distributed-query/carve records, and console/file-explorer rows have no uniform background retention policy. Query expiration changes lifecycle state rather than deleting rows.
- Relationships mostly use indexed numeric IDs, UUIDs, or names without database foreign-key constraints. External routes also mix environment names/UUIDs, node UUIDs/names, and numeric configuration IDs, which matters when integrating or troubleshooting.
- SAML assertion replay protection uses a per-process TTL cache. In a multi-replica API deployment, the same assertion can be presented once to each replica within its validity window unless a shared replay layer is added.
- Graceful shutdown is limited. `osctrl-api` drains HTTP requests for an internally requested config restart, while `osctrl-tls` exits for its restart command; neither service currently installs a general OS-signal shutdown path.
