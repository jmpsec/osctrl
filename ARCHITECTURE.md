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
- `pkg/health`: deployment health — the `service_status` heartbeat table, component status derivation (operational/degraded/down/stale/unknown), Go runtime snapshots, and a 24h-refreshed upgrade-version cache. Gated by `--health-enabled` (default off).
- `pkg/nodes`: node registry, lookup, archive, metadata updates.
- `pkg/nodeconfig`: per-node osquery configuration and flags overrides (validation, merge rules, Redis-backed caches) and the osctrld status record.
- `pkg/extensions`: osquery extension library (files up to 64 MB stored in the database as 1 MiB chunks shared by SHA-256), environment and host assignments, per-node status, and the serve-time enforcement of who may receive what.
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
- `pkg/vulns`: optional vulnerability monitoring — inventory ingestion (TLS), OSV/CISA KEV (and optional NVD) feed sync, matching and findings (API worker), read model. It also supplies posture score evidence and the advisory-feeds health component.
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

- `osctrl-tls` wires Redis-backed environment/settings/query-dispatch caches, node activity batching, node metadata batching, persisted log sinks, service-command polling, and optional DB-health, posture, vulnerability-inventory, alerting (including the vulnerability-finding watcher), and Prometheus components. When `--health-enabled` is set, it also writes a `service_status` heartbeat (version, uptime, goroutines, worker counters) every 60s by riding the existing 5s service-command poll loop rather than starting a new ticker.
- `osctrl-api` wires the shared environment/query caches and activity reader; initializes audit, MFA, console, file-explorer, service-config, log-sink, and auth-provider managers; and conditionally registers posture, vulnerability (plus its feed-sync worker, single-active across replicas through a SQL lease), alerting, service-management, federated-auth, and hosted-MCP routes.

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
  - `GET /api/v1/health/status` when `health.enabled` is true (admin only, 503 when disabled)
  - `/api/v1/mcp` when `mcp.enabled` is true

Request controls are composed at route registration:

- `cmd/api/auth.go`: `handlerAuthCheck(...)` accepts a bearer JWT or the SPA's JWT cookie, verifies it against the user's currently stored token, enforces CSRF on cookie-authenticated mutations, and attaches the username to request context.
- Login, pre-auth discovery, service-config apply, and TLS enrollment have configurable in-memory per-IP rate limits.
- `osctrld` routes in `osctrl-tls` (`rateLimits.osctrldAuth`, `osctrld`, `osctrldDownload`; `cmd/tls/handlers/osctrld_limits.go`): every request is limited per client IP (default 300/min, extension downloads also 30/min), and wrong environment secrets are charged to a per-IP-and-environment budget (default 10/hour). Once that budget is spent the IP gets 429 with `Retry-After` on that environment's `osctrld` routes, even with the right secret: checked before the body is read, and again atomically with the secret comparison (`ratelimit.Limiter.Attempt`), so concurrent requests cannot exceed it. Correct secrets never charge it, so hosts sharing a NAT are unaffected. The client IP is `utils.GetIP`: behind a reverse proxy or load balancer, `service.trustedProxies` must list it, otherwise all clients share the proxy's budgets and one bad client can block the fleet. Past `maxBuckets` tracked keys, new keys share one overflow budget and are blocked together. Every wrong secret is audited (while blocked, one rejection per budget period per IP and environment), capped at 60 audit entries per hour per environment; drops are counted. Metrics: `osctrld_auth_failures_total{environment}`, `osctrld_rate_limited_total{route,limit}`, `osctrld_auth_audit_dropped_total{environment}`, and request duration/status by route pattern. Limits are per process.
- `cmd/tls/handlers/handlers.go`: `PrometheusMiddleware(...)` records request duration/status for enabled osquery-facing endpoints; handlers also apply endpoint-specific body-size caps.

`osctrl-tls`, under `osctrld.enabled` and when per-node flags overrides are wired, also serves `POST /{env}/osctrld-status` (body <= 4 KiB, secret in the body, through the same rate-limited middleware). osctrld reports whether osqueryd is running, since when it is down, and its last flags and extensions rollback (`stage`, `event_id`); the report is stored in `node_osctrld_status`. A malformed body, a bad UUID or a UUID that is not a node of the environment gets 400 (never 404, which osctrld reads as "route not served"); invalid stages or event ids are dropped for that kind. Each new rollback event id is counted and audited once (compare-and-set, so replicas agree): `osctrld_rollbacks_total{environment,kind,stage}` and a warning audit entry (`osctrld rollback on node <uuid> in env <env>: <kind> <stage>`). A scrape-time collector exports `osctrld_osquery_down{environment}` for every environment (0 when none), counting nodes whose report is fresher than `nodeconfig.ReportFreshness` (15 min) and says osqueryd is down; on a database error or timeout it exports nothing for that scrape and backs off for a minute. Operator semantics: `osctrld_osquery_down` is derived from the database, so every `osctrl-tls` replica exports the same value; aggregate with `max by (environment)`, never `sum`. `osctrld_rollbacks_total` is counted by one replica only (compare-and-set), so `sum` is correct. The report may also carry an `upgrade` object (the result of osctrld's last osquery upgrade: `result` `ok|rejected|skipped`, `version`, `reason`, `request_id`, `event_id`); a valid one overwrites the `upgrade_*` columns of `node_osctrld_status`, an invalid one is dropped without touching the rest of the report. A `rejected` result is a rollback: its `event_id` is deduplicated by the same compare-and-set (on `upgrade_event_id`) and counted once as `osctrld_osquery_upgrade_rollbacks_total{environment}` plus a warning audit entry (`osctrld osquery upgrade rolled back on node <uuid> in env <env>: <version> (<reason>)`); one replica counts each event, so `sum` is correct for it too. A second scrape-time collector, `osctrld_osquery_behind{environment}`, counts nodes whose report is fresh and whose stored `osquery_version` is lower than their effective target (an unexpired pin of the node's environment, else the environment target; no target, an empty or unparseable version, or a node on a platform without a package (`freebsd`), is not counted; Windows nodes count; the report and the node row are joined on UUID and environment, so a stale row left by re-enrolling into another environment is ignored); it is exported for every environment (0 when none), has the same cache, timeout and backoff behavior, is registered only when the osquery version library is enabled, and is aggregated with `max by (environment)` like the down gauge. A third collector, `osctrld_osquery_rollout_paused{environment}`, is 1 for an environment whose latest rollout row is stored as paused (a newer running, aborted or completed row replaces it) and 0 otherwise, for every environment, with the same cache, timeout, backoff and registration conditions; it is database-derived, so aggregate with `max by (environment)` across replicas. The node's stored `osquery_version` comes from the `osquery_version` decoration of its logs or, when a batch carries none (a default environment has an empty schedule and may send undecorated status logs only), from the top-level `version` of its status logs (the most recent valid one; anything that is not a valid version is ignored); until one arrives the stored version is stale, so an upgraded host can still count as behind. Pair an alert on the gauge with an `absent()`/staleness rule if a database outage must not resolve it. A host counts as down only while its latest report is under 15 minutes old. A `rejected` result carrying a 32-hex `request_id`, from a node of the environment, also pauses the environment's osquery rollout when that id is the current running rollout's (compare-and-set in `PauseRollout`, so a pin's or an older target's id, a rollout already paused, aborted or replaced is a no-op), whether or not the rollback event was new; the first host to pause is recorded (display name hostname, else localname, else UUID) and a warning audit entry (`osquery rollout paused in env <env>: <version> rolled back on <host> (<reason>)`) is written once, only when this report paused it. A rollback only pauses if it was first recorded (server time, `node_osctrld_status.upgrade_event_at`, set in the same compare-and-set as the event id; host clocks are never used) after the rollout was last resumed (`osquery_rollouts.resumed_at`), so an osctrld that keeps re-reporting the old rejected result cannot undo a Resume; a genuinely new rollback after the resume pauses again. A failed pause write answers 500; the rollback's event id is already stored, so the next report of the same result repairs it. `skipped` results never pause. The reasons `rollout_pending` and `rollout_paused` are valid for `skipped` (and by the generic rules `rejected`) results: the host is not yet eligible in the open stage, or the rollout is paused and the host has not upgraded. The reason `rollback_unavailable` is valid for `rejected` results: osctrld on Windows reports it when an upgrade failed and the previous version could not be restored, so the host needs manual repair; it counts as a rollback (event counted and audited once) and pauses the rollout like any other rejected rollback. An older `osctrl-tls` answers 405 (not 404) to unknown POST routes; osctrld treats both as "not supported".

`osctrl-tls`, under `osctrld.enabled`, also serves `POST /{env}/osctrld-osquery` (body <= 4 KiB, secret in the body, through the same rate-limited `OsctrldMiddleware`) so `osctrld` can ask which osquery version to run. Request: `{secret, uuid, platform, arch, format, installed_version}`; `platform`, `arch` and `format` must match `^[a-z0-9_]{1,16}$` and `installed_version` must be empty or a valid version. Response `200`: `{reason, source, request_id, target, previous, reported_version}`. `reason` is always present and empty means upgrade (`target`, `{version, sha256}`, is then present, and so is `previous` except for Windows, which gets the target only and never `no_digest_for_installed`); otherwise it is `no_target`, `ahead_of_target`, `no_digest_for_target`, `no_digest_for_installed` or `unsupported_platform`. `source` (`environment` or `pin`) and `request_id` are present whenever a target exists and omitted for `no_target` and `unsupported_platform`. `reported_version` is the node's stored `osquery_version`. The route never answers 404: a malformed body, a bad UUID, malformed tokens or a UUID that is not a node of the environment (identical empty body for unknown and other-environment nodes) get 400, a wrong secret 403, a database error 500; a well-formed but unsupported combination (for example `freebsd`/`pkg`) is a 200 with `unsupported_platform`. The decision is `osqueryversions.Manager.Resolve`; the route is registered only when that manager is wired.

Windows hosts need the new osctrld to upgrade (the Windows MSI path); until then they count as eligible/waiting in rollout progress and as behind in `osctrld_osquery_behind`, like hosts of other platforms that lack osctrld. Windows MSI upgrades are amd64 only (`windows/386` is `unsupported_platform`).

A new `request_id` tells osctrld to try a target again, including one the host rejected. Setting an environment target always gets a new one. A node pin gets a new one unless only its expiry changed (same environment and version, an `expires_at` at least a second apart), so extending a pin does not retry a rejected version; re-saving the same version with the same expiry is how an operator retries.

Confirmation load: after installing a new version, each upgrading host polls this route about every 30 seconds for up to 5 minutes (about 10 requests) until `reported_version` shows the new version. Those requests count against `rateLimits.osctrld` (default 300/min per client address). Behind a NAT, or with a missing or wrong `service.trustedProxies`, many hosts share one budget, so a very large simultaneous rollout through one address can exhaust it: a 429 makes osctrld wait (honoring `Retry-After`) and retry, and a host whose confirmation window runs out is rolled back with `version_not_reported`. Mitigate with `trustedProxies` and by rolling out in stages (pins, or environment targets set one environment at a time).

There is no global middleware chain or declarative authorization policy. Authentication wrappers, rate limits, feature gates, and permission checks are attached explicitly to routes and handlers.

Optional live updates use `GET /api/v1/events?env=<name-or-uuid>&topic=queries`
(also `topic=carves`, repeatable). Session-scoped topics are also supported:
`topic=console&console_session=<id>` and
`topic=file_explorer&file_explorer_session=<id>`. Alert administration uses
`topic=alerts`; the top-level Alerts page may use `env=all` for one
super-admin stream covering global and environment-scoped alert changes.
Service-command status hints use `topic=service_commands` with `env=all` and
super-admin access. Fleet activity hints use `topic=fleet` with `env=all` and
super-admin access, then coalesce dashboard and node-list refreshes. Enable
`service.eventsEnabled` / `--events-enabled` on API and TLS and set
`service.eventsNamespace` / `--events-namespace` to the same deployment-unique
value. Both default to disabled/unset. The equivalent environment variables are
`SERVICE_EVENTS_ENABLED` and `SERVICE_EVENTS_NAMESPACE`. Namespaces use 1–64
letters, digits, underscores, or hyphens and isolate deployments sharing Redis,
including deployments using different Redis database numbers.

`pkg/events` publishes bounded, best-effort Redis Pub/Sub invalidation hints and
fans them out to API subscribers. Each connection is scoped to an environment
and authorized query/carve topics; console and file-explorer hints also require
AdminLevel plus creator ownership of the selected active session, while alert,
service-command, and fleet hints require super-admin permissions. The API rechecks token validity and
permissions before each batch and during idle heartbeats. Broker reconnects and
slow-subscriber overflow close streams so the frontend obtains fresh REST
snapshots. The environment layout shares one fetch-based SSE stream between
query/carve views; console and file explorer open session-specific streams after
session creation; the Alerts page opens an alerts-only stream and invalidates
rules, channels, or history snapshots; dashboard and node-list pages open a
fleet stream and coalesce activity invalidations. Hints do not guarantee result
persistence, operation completion, replay, dispatch delivery, or download
availability. Commands, pagination, result data, alert rows, and downloads
continue through REST. No WebSocket transport is used.

When health reporting is enabled, `/api/v1/health/status` includes a live
updates component with API subscriber counts and API/TLS drop counters. The
details intentionally omit users, environment UUIDs, query names, and payloads.

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
- HTTP handlers use `CheckPermissionsContext` with a request-scoped cache. Authentication seeds the user row; each environment's permission rows are loaded once per request. Streams create a fresh snapshot for every batch and heartbeat, preserving database-authoritative revocation across replicas and CLI changes. No permission snapshot is reused between requests or stream batches.

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
- **Precedence: pinned fields beat flags and environment variables; nothing else does.** Each `service_configs` row holds a whole section as JSON plus `overrides`, the list of top-level fields an operator pinned. On boot a service seeds its sections from the flags/env/YAML it started with, keeps every *unpinned* field of an existing row equal to that configuration (so the stored value, which the UI shows as the current setting, matches what is running), then applies only the *pinned* fields on top. The service-config API pins per field: `PUT` with `patch` pins the named fields, `reset` releases them (the last release returns the row to `source=yaml`), and the Service Config page sends only the fields it changed, so editing a log level no longer freezes the port. A `value` body still replaces a whole section and pins every field in it. A `source=db` row with an empty `overrides` is a row from before per-field overrides, or one replaced as a whole, and pins everything: that is the only reading that cannot silently drop an edit, since the original YAML is gone once a row is overwritten, so upgrading changes nothing until an operator releases fields. Stored rows keep applying after `--service-config-enabled` is switched off; that flag only controls whether the API and page exist. "Write to disk" persists only pinned fields into the YAML file and clears the pins. `Resolve` logs, at Info, each field a database row changes, with both values (values only for editable sections, never for credential-bearing ones). Granularity is the section's top-level fields, so editing a nested value such as one rate limit pins that whole limit. Rows with `source=yaml` pin nothing.
- Sensitive or connection-bearing sections are read-only through the service-config API. Log sinks and federated auth providers have dedicated tables and APIs.
- `osctrl-tls` reads its settings map through `RedisSettingsCache`; the normal cache TTL is five minutes unless a TLS-scoped `refresh_settings` row is present. The API reads scalar settings directly from the database.

Node inactivity uses `api/inactive_hours`: an environment override, then the
global row (`EnvironmentID = 0`), then 72 hours. Values are positive whole hours,
bounded at 2,562,047 to avoid overflowing Go durations. Missing or invalid legacy
rows inherit; new invalid values are rejected. Existing installations keep their
global value without a migration or per-environment backfill.

Environment Settings exposes an override and a "Use global default" control.
`GET /api/v1/environments/inactive-hours/{env}` returns `override_hours` (nullable),
effective `inactive_hours`, and `source` (`environment`, `global`, or `default`).
Environment users can read; environment admins can `PUT {"inactive_hours": 2}`
or `DELETE` to restore inheritance. Global settings remain global-admin-only.
Override writes serialize on the environment row; deleting an environment also
removes its inactivity override.

Node filters, health, dashboard counts, CLI, active query/carve selectors, and TLS
inactivity alerts use the node's environment threshold. Per-environment stats
include their effective `inactive_hours`; the top-level field is retained as the
global default, not a universal fleet cutoff. A node is inactive at or before
`now - inactive_hours`, including never-seen nodes.

Inactivity thresholds are read directly from SQL by API and TLS (not the TLS
settings cache), so no restart is needed. Browser views refresh on their normal
polling interval and invalidate relevant queries after saves. Alert sweeps use
the new threshold on their next pass: shortening it may emit inactive alerts;
lengthening it may emit recovery alerts even without a new check-in. Existing
alert transition deduplication remains in effect. Update all service/client
consumers before configuring overrides during a rolling deployment.

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
- Created from API and hosted MCP actions such as login, node/query/carve mutations, explicit downloads, settings changes, and MCP tool calls. Routine successful REST reads and polling do not create audit rows. TLS records successful and failed enrollment and consumed service-control events.
- Successful enrollment/re-enrollment uses `LogTypeEnroll` (12), after node persistence succeeds. The audit-backed environment activity endpoint counts only that type as enrollment; generic node events, including historical viewed rows, are excluded. Query actions use `LogTypeQuery`. Earlier successful enrollments were not audited, so historical enrollment counts are not reconstructed from generic node events.
- The API seeds the global `api/audit_log_retention_days` integer setting (90 days; valid range 1–36500). It can be edited through the settings API. If older audit history must be retained on upgrade, preconfigure its global `setting_values` row before starting the upgraded API. At startup and hourly, the API physically deletes expired rows from all services, including soft-deleted rows, in batches of 1,000, with a 100 ms pause and five-minute sweep limit. Pruning runs even if new audit writes are disabled. Invalid settings or setting-read failures stop cleanup. API replicas may safely race; no cleanup worker runs when the API is stopped.
- DB log startup builds `(uuid, created_at)` indexes before removing the redundant status/result UUID indexes. PostgreSQL replacement indexes must be valid and not building before removal; drops use `CONCURRENTLY`. The UUID column retains its original `varchar(191)` type on MySQL and `text` type on PostgreSQL/SQLite, avoiding a column rewrite. The query-log UUID index stays because `(name, created_at)` does not cover it. Complete rollout of the new logger code before relying on removal: an older process can recreate the old indexes at startup.

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
7. It returns `env.Configuration` as the osquery config payload, with the node's per-node override (`pkg/nodeconfig`) deep-merged on top when one exists and has not expired.

Per-node configuration overrides are admin-only (environment admin, enforced server-side and audited) and layered on the environment configuration: objects merge key by key, other values replace, and environment changes keep reaching the node. Options that keep the host connected to osctrl (e.g. config/logger/distributed/enroll TLS settings, host identifier) and `null` values are refused. The override applies only while the node is in the environment it was saved for, and an invalid stored override falls back to the environment configuration. An override may carry an expiry (none by default); an expired one stops applying and stays listed until removed. Changes take effect on the host's next config fetch; osquery does not reset options that the environment doesn't set, so those keep their overridden value until osquery restarts.

Per-node flags overrides (`GET|PUT|DELETE /api/v1/nodes/{env}/node/{uuid}/flags`, same admin/audit/expiry rules) follow the same model for the osquery flagfile. The text is one flag per line (`--name` or `--name=value`); connection flags (including their `no<name>` forms) are refused, while flags also set as configuration options are listed as conflicts (a warning, not refused). The override merges into the environment flags by name (replacing a flag in place, appending new ones). Only `osctrld` reads flags, and only in service mode, so the override reaches a host when osctrld's sync request carries that host's osquery UUID (`uuid`, from `system_info.uuid`) and the UUID matches the node: `osctrl-tls` then merges the active override into the osctrld `flags` and `verify` responses and records the fetch in `node_osctrld_status`. osctrld reports the outcome of its last flags change (`apply`); because osquery exits on a flag it rejects, osctrld checks that `osqueryd` stays running after a restart, otherwise restores the environment flags, restarts, reports `rejected` and does not re-apply that content while it is served. Flags apply on the next sync (default 60 minutes) with an osquery restart and fully revert on removal or expiry. Deleting a node (API or CLI) removes its overrides and osctrld status.


### osquery extensions

`pkg/extensions` delivers osquery extension binaries to hosts through `osctrld`. Only super admins manage the library under `/api/v1/extensions`: `POST` creates an extension (JSON), and a multipart `PUT /api/v1/extensions/{id}/files/{platform}/{arch}` (field `file`, ≤ 64 MB) uploads the binary for one platform/architecture. A file is stored in the database as 1 MiB chunks keyed by SHA-256, so identical content is stored once. Assignment follows the risk of the extension: environment admins assign ordinary extensions to an environment (`/api/v1/environments/extensions/{env}[/{id}]`), while extensions marked as executing commands are assigned only by super admins, per host and with an optional expiry (`/api/v1/nodes/{env}/node/{uuid}/extensions[/{id}]`; environment admins can view them, and the expiry key must be present in the request). The split is enforced when serving, not only in the API: an environment assignment never delivers a command-execution extension, and each host's list is computed per host (the environment's extensions plus that host's own unexpired command-execution assignments). Downloads are authorised by the environment secret and limited, by content hash, to files assigned in that environment, not per host. Extension names are unique ignoring case, since hosts may have case-insensitive file systems. Deleting a node removes its assignments and statuses; deleting an extension removes the statuses reported for it; removing a host assignment removes that host's status for it, unless the status is `kept`. `osctrld` reports a removal as `removed`, or as `kept` when it failed and the extension is still on the host (repeated every sync while it stays); a `kept` command-execution extension the host has no unexpired assignment for (removed or expired) is flagged on the node page, ahead of the expired wording, until a later report replaces it, and meanwhile the extension cannot be deleted from the library or have command execution switched off.

`osctrl-tls`, under `osctrld.enabled`, serves `POST /{env}/osctrld-extensions` (the list for the host's UUID and platform/architecture, which also records the status `osctrld` reports; a request without platform and architecture, from an `osctrld` that predates extensions, gets an empty list) and `POST /{env}/osctrld-extension` (download, body `{secret, sha256}`; the hash must belong to a file assigned to the environment or, unexpired, to a host in it). Hosts must run `osctrld` in service mode and pick up changes on its next sync (default 60 minutes). `osctrld` verifies size and SHA-256, installs files root-owned, manages only its own autoload lines (the autoload file must be a `*.load` file directly in osquery's base directory, otherwise it is refused and reported), checks that each extension's process runs after the osquery restart, and rolls back failures and reports them; the node page shows the per-extension status. The operator UI exposes Admin › Extensions (library), the environment Configuration › Extensions tab and the node Configuration › Extensions view.

Because uploads go through nginx, the `/api/` location in the frontend configs allows 65 MB bodies. The direct API vhost that `deploy/provision.sh` builds from `deploy/nginx/ssl.conf` inherits the global `client_max_body_size 20M` from `deploy/nginx/nginx.conf`, so uploads over 20 MB through it fail until `client_max_body_size` is raised for that vhost.

### Steady-state database load

- Node check-ins are coalesced per TLS process and persisted in parameterized bulk updates of at most 100 nodes. Each node retains its observation timestamp, normalized to database precision; older observations cannot replace newer timestamps or IPs. Equal stored timestamps keep the first persisted IP. The existing writer batch size, timeout, and buffer settings still control collection. The queue remains process-local and best-effort on shutdown or database errors; it is not a durable heartbeat store.
- Empty distributed-query results are cached in Redis for two minutes by default, configurable through `osquery.queryDispatchTTL`, `--query-dispatch-ttl`, or `QUERY_DISPATCH_TTL`. Non-positive values select the default. Query creation invalidates targeted nodes; Redis `WATCH` prevents an in-flight empty SQL result from refilling an invalidated entry. SQL errors are not cached, and TLS returns HTTP 503 so agents can retry.
- When acceleration is disabled, query reads skip session checks entirely. Otherwise, shared console/file-explorer hints cache absence for two minutes and presence for at most five seconds, bounded by the existing 30-second session freshness window. Session mutations invalidate hints after committing; token-checked refills reject obsolete lookups. These hints control polling only, never authorization.
- Redis failures fall back to SQL. Failed invalidations can delay query discovery by the configured dispatch TTL or session acceleration by two minutes. Direct-database CLI mode has no Redis connection and also relies on dispatch TTL expiry; use API-mode query/carve submission for immediate invalidation. Upgrade all API/TLS replicas before relying on race-safe invalidation; old replicas do not implement the new refill protocol. Longer TTLs trade fewer SQL reads for a larger failure-time staleness window.
- Real-engine regression tests are opt-in: `OSCTRL_TEST_POSTGRES_DSN` and `OSCTRL_TEST_MYSQL_DSN` exercise bulk updates using temporary prefixed tables. `OSCTRL_TEST_REDIS_ADDR` exercises query/session cache races against a disposable Redis instance; the optional `OSCTRL_TEST_REDIS_CONTAINER` test restarts that disposable container and requires a fixed host port.

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

Feature-owned tables are migrated only when their manager is initialized. In particular, posture, alert and vulnerability tables require those features to be enabled; osquery log tables require a DB logger.

- Environments:
  - `pkg/environments.TLSEnvironment` -> `tls_environments`
  - `pkg/environments.EnvironmentPackage` -> `environment_packages`
- Nodes:
  - `pkg/nodes.OsqueryNode` -> `osquery_nodes`
  - `pkg/nodes.ArchiveOsqueryNode` -> `archive_osquery_nodes`
  - `pkg/nodeconfig.Override` -> `node_config_overrides`
  - `pkg/nodeconfig.FlagsOverride` -> `node_flags_overrides`
  - `pkg/nodeconfig.OsctrldStatus` -> `node_osctrld_status`
- Extensions:
  - `pkg/extensions.Extension` -> `extensions`; `ExtensionFile` -> `extension_files`; `ExtensionChunk` -> `extension_chunks`
  - `pkg/extensions.EnvExtension` -> `env_extensions`; `NodeExtension` -> `node_extensions`; `NodeExtensionStatus` -> `node_extension_statuses`
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
- Vulnerabilities (only with `--vuln-enabled`):
  - `pkg/vulns.NodeSoftware` -> `node_software`
  - `pkg/vulns.NodeState` -> `vuln_node_state`
  - `pkg/vulns.Advisory` -> `vuln_advisories`
  - `pkg/vulns.Alias` -> `vuln_aliases`
  - `pkg/vulns.Affected` -> `vuln_affected`
  - `pkg/vulns.KEV` -> `vuln_kev`
  - `pkg/vulns.CPEProduct` -> `vuln_cpe_products`
  - `pkg/vulns.Finding` -> `vuln_findings`
  - `pkg/vulns.Escalation` -> `vuln_escalations`
  - `pkg/vulns.SyncState` -> `vuln_sync_state`
  - `pkg/vulns.WorkerState` -> `vuln_worker_state`
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
- Health:
  - `pkg/health.ServiceStatus` -> `service_status` (one upserted row per reporting service; created only when `--health-enabled` is set)

Redis-only state such as activity rollups, query-dispatch hints, and alert cooldown/inactive markers is not represented in these tables. Important relationships are implemented through indexed ID/UUID fields and application code rather than database foreign-key constraints.

## Deployment Notes

- Dev stack: [`docker-compose-dev.yml`](./docker-compose-dev.yml) runs nginx, the React frontend, `osctrl-tls`, `osctrl-api`, Postgres, Redis, CLI bootstrap, and sample osquery clients.
- Production-oriented assets live under `deploy/`:
  - sample YAML configs in `deploy/config/*.yml`
  - systemd unit template in `deploy/config/systemd.service`
  - nginx config in `deploy/nginx/` (extension uploads need `client_max_body_size` of 65m on the API location; the direct API vhost from `provision.sh` inherits 20M, see the osquery extensions section)
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

- Service-config pins are per top-level field, and a nested value pins as a unit. Rows created before per-field overrides pin every field in their section until an operator releases them (the startup log names each such row); there is no automatic migration because the information needed to infer which fields were really edited no longer exists. During a rolling upgrade an older process treats any row as a whole-section override, which is exactly the old behavior. `configEndpoints`, an array section, cannot be pinned per field and is neither refreshed on boot nor patchable.
- Schema evolution uses GORM `AutoMigrate` from manager constructors. There is no ordered, versioned migration framework or explicit rollback path, so model changes run during service startup.
- A configured SQL backend (PostgreSQL, MySQL, or SQLite) and Redis are startup dependencies for both HTTP services. Redis failures are not treated as an optional cache outage.
- DB degraded mode is opt-in and only helps paths whose required environment/settings entries are already warm in Redis. It does not make general API CRUD or other database-backed operations available; continued TLS ingestion also depends on warm node state and the configured log sink.
- The node-key cache, alert rule snapshots, live exporter state, and rate-limit buckets are process-local. Several refresh, retention, stats, inactive-node, and service-command workers run inside their owning service process; there is no general leader-election layer for horizontally replicated services.
- The API and TLS services share tables and packages directly. API config restart is signaled in-process; restart/reload/persist requests targeting TLS use the database-backed `service_commands` queue rather than a service-to-service API.
- Database-backed auth-provider activation is incomplete. Provider discovery advertises ID-scoped login URLs, but the API registers only the legacy YAML-gated OIDC/SAML public routes. In addition, `POST /api/v1/auth-providers/apply` targets `osctrl-tls` with `reload-auth-providers`; the TLS watcher does not handle that action and the API has no command consumer. Use YAML/flag providers for working federated login until the ID-scoped routes and API-side reload path are completed.
- Authentication is centralized in route wrappers, but environment authorization remains a handler-by-handler `CheckPermissions` responsibility. There is no declarative policy layer to prevent permission drift between related endpoints.
- Scalar-setting changes do not explicitly invalidate `osctrl-tls`'s Redis settings entry, so cached TLS settings change after its cache TTL. Inactivity thresholds bypass this cache. Environment mutations through `osctrl-api` invalidate the shared Redis environment cache (`osctrl:tls:environment:<uuid>`) immediately, but `osctrl-cli --db` edits (environment update/add/delete, config edits, rotate/extend/expire actions, new-flags) have no Redis connection and cannot: `osctrl-api` and `osctrl-tls` may serve the old environment until the entry expires (5 minutes, 60 while the database health monitor reports degraded). Use API-mode CLI commands for immediate effect.
- Retention is feature-specific: activity rollups expire in Redis and alert history is pruned daily when alerting is enabled, but osquery log rows, distributed-query/carve records, and console/file-explorer rows have no uniform background retention policy. Query expiration changes lifecycle state rather than deleting rows.
- Relationships mostly use indexed numeric IDs, UUIDs, or names without database foreign-key constraints. External routes also mix environment names/UUIDs, node UUIDs/names, and numeric configuration IDs, which matters when integrating or troubleshooting.
- SAML assertion replay protection uses a per-process TTL cache. In a multi-replica API deployment, the same assertion can be presented once to each replica within its validity window unless a shared replay layer is added.
- Graceful shutdown is limited. `osctrl-api` closes event streams and drains HTTP requests for config restart, SIGINT, or SIGTERM. `osctrl-tls` exits for its restart command and has no general OS-signal drain path.
- Health reporting needs `--health-enabled` on both services to show a complete picture: with only `osctrl-api` enabled, the page shows `osctrl-tls` as "not reporting" (unknown), never "down", since there is no heartbeat row to compare against. Multiple `osctrl-tls` replicas share the single `service_status` row for `"tls"` — the last writer wins, so overall liveness stays correct but per-replica detail (which instance, how many) is lost. The health page is a point-in-time snapshot with no history.
