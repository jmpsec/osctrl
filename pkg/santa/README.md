# pkg/santa

Optional Santa (North Pole Security, macOS) sync server. Disabled by default; enable with `--santa-enabled` (env `SERVICE_SANTA_ENABLED`, YAML `service.santaEnabled`) on both `osctrl-tls` and `osctrl-api`. Requires a restart. When off, no tables are migrated, no TLS or API routes are registered and `/api/v1/features` reports `santa: false`.

Tables (`santa_env_configs`, `santa_rules`, `santa_machines`, `santa_events`) are migrated only when `santa.NewManager` is constructed.

## Data flow

- `osctrl-tls` serves the Santa sync protocol (v2): `POST /{env}/santa/sync/{stage}/{machineid}` with `stage` one of `preflight`, `eventupload`, `ruledownload`, `postflight`. `{env}` is the environment UUID, `{machineid}` the node UUID.
- `osctrl-api` manages configuration, the token, rules, and read views of machines and events under `/api/v1/santa/{env}/...` (`config`, `token`, `rules`, `machines`, `events`). The React UI (Santa page) calls these. JSON is snake_case.
- Both share the SQL database. Rules are scoped to the environment, a tag, or a node. For each (rule type, identifier) the most specific scope wins (node over tag over environment).

### Digest-based clean sync

At preflight osctrl computes the node's effective rules and an order-independent SHA-256 digest of their synced fields. The digest is stored on the machine as `pending_digest`. If it differs from the `applied_digest` (or the client asked for a clean sync) osctrl answers `CLEAN_RULES`, and the client downloads the full set (500 rules per `ruledownload` page); otherwise `NORMAL`. At postflight `pending_digest` becomes `applied_digest`. The preflight digest is the one stored, so rule or tag changes between preflight and postflight are picked up by the next sync rather than being recorded as applied.

Events uploaded by clients are stored in `santa_events` (fields truncated to 255 characters). Retention is fixed at 30 days; `osctrl-api` prunes daily.

## Authentication model

- Each environment has one token, sent by Santa in the header `X-Osctrl-Santa-Token`. Only its SHA-256 is stored and it is compared in constant time. Generate or rotate it with `POST /api/v1/santa/{env}/token` (environment admin); the plaintext is returned once (`Cache-Control: no-store`) and the old token stops working immediately. Reading the config never returns the token.
- The machine ID in the URL must be a UUID of a node already enrolled in osquery in that same environment. A malformed (non-UUID) machine ID gets `400`. Unknown or other-environment machines get `403`, as do unknown environments and wrong tokens (no existence oracle).
- If the effective rule set changes mid-sync, `ruledownload` returns `409` and the client retries on its next sync.
- Requests are not IP rate limited (that would throttle fleets behind one NAT). Failed authentications are written to the audit log, capped at 60 per hour per environment; drops are counted in the Prometheus metric `santa_auth_audit_dropped_total`.
- Bodies: JSON or protobuf, optionally gzip or zlib compressed; the raw body is capped at 10 MiB and the decompressed body at 20 MiB (`413` past either limit). Responses use the request's encoding.
- Management routes require environment admin permission and write an audit line (`santa: <action>`). Creating a duplicate rule returns `409`.

### Trust model limits

The token is per environment and is present on every Santa host in it, and machine IDs (hardware UUIDs) are not secret. Any host holding the token can therefore sync as any enrolled node in the same environment: read its tag- and node-scoped rules and upload events for it. Where that matters, require client mTLS at the reverse proxy in front of `osctrl-tls` (Santa's `ClientAuthCertificate*` configuration keys). osctrl does not verify client certificates itself.

## Santa configuration profile

Set the keys in the `com.northpolesec.santa` payload of your MDM configuration profile:

```xml
<key>SyncBaseURL</key>
<string>https://osctrl.example.com/ENVIRONMENT-UUID/santa/sync/</string>
<key>SyncExtraHeaders</key>
<dict>
    <key>X-Osctrl-Santa-Token</key>
    <string>TOKEN-FROM-THE-UI</string>
</dict>
<!-- Optional: use protobuf transfers instead of JSON -->
<key>SyncEnableProtoTransfer</key>
<true/>
```

Leave `MachineIDKey` unset so the machine ID is the hardware UUID, which must match the osquery node UUID. The trailing slash on `SyncBaseURL` is required.

## Not implemented

The `commands`, `metrics` and `signalupload` stages; FCM/NATS push; file-access, network-flow and telemetry rules; bundle uploads; forwarding Santa events to alert rules or log sinks; MCP tools.
