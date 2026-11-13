# pkg/santa

Optional Santa (North Pole Security, macOS) sync server. Disabled by default; enable with `--santa-enabled` (env `SERVICE_SANTA_ENABLED`, YAML `service.santaEnabled`) on both `osctrl-tls` and `osctrl-api`. Requires a restart. When off, no tables are migrated, no TLS or API routes are registered and `/api/v1/features` reports `santa: false`.

Tables (`santa_env_configs`, `santa_rules`, `santa_mode_overrides`, `santa_machines`, `santa_events`) are migrated only when `santa.NewManager` is constructed.

## Data flow

- `osctrl-tls` serves the stable Santa sync protocol (v1, `santa.sync.v1`): `POST /{env}/santa/sync/{stage}/{machineid}` with `stage` one of `preflight`, `eventupload`, `ruledownload`, `postflight`. `{env}` is the environment UUID, `{machineid}` the node UUID.
- `osctrl-api` manages configuration, the token, rules, and read views of machines and events under `/api/v1/santa/{env}/...` (`config`, `token`, `rules`, `modes`, `machines`, `events`). The React UI (Santa page) calls these. JSON is snake_case.
- Both share the SQL database. Rules are scoped to the environment, a tag, or a node. For each (rule type, identifier) the most specific scope wins (node over tag over environment).

### Digest-based clean sync

At preflight osctrl computes the node's effective rules and an order-independent SHA-256 digest of their synced fields. The digest is stored on the machine as `pending_digest`. If it differs from the `applied_digest` (or the client asked for a clean sync) osctrl answers `CLEAN_RULES`, and the client downloads the full set (500 rules per `ruledownload` page); otherwise `NORMAL`. At postflight `pending_digest` becomes `applied_digest`. The preflight digest is the one stored, so rule or tag changes between preflight and postflight are picked up by the next sync rather than being recorded as applied.

Events uploaded by clients are stored in `santa_events` (fields truncated to 255 characters). Retention is fixed at 30 days; `osctrl-api` prunes daily.

### Events in log sinks and alert rules

After an upload is stored, `osctrl-tls` forwards its events to the log sinks and the alert rules. Both are optional and need no Santa-specific setting.

- **Log sinks:** each upload is sent as one JSON array of events under the category `santa` (the same fields as `GET /api/v1/santa/{env}/events`). A sink with no category filter receives it; a filtered sink needs `santa` in its categories. The DB sink ignores it, since the events are already in `santa_events`. If a sink fails, the error is logged and the upload still succeeds, because the events are stored and a retry would store them twice.
- **Alert rules:** rules with the source `santa_event` match on the event fields `decision`, `file_sha256`, `file_path`, `file_name`, `executing_user`, `team_id`, `signing_id`, `cd_hash` and `bundle_id`, with the usual substring or regex pattern, on one field or on any. For example, field `decision` with pattern `BLOCK` alerts on every blocked execution. A rule alerts once per node and file hash within its cooldown. These rules need the same permission as log-content rules (superuser or full query tier), and `osctrl-tls` needs `--alerts-enabled`.
- Event fields are written by the Santa client and are untrusted. The notification detail is one line (`DECISION path sha256=... user=...`) with control characters removed and at most 1024 bytes.
- The osquery log endpoint rejects the log type `santa`, so an osquery node cannot forge Santa events into the sinks.

### Bulk import and export

Rule sets can be moved between environments or kept in git.

- **Export:** the rule list as JSON, holding only the portable fields (`identifier`, `rule_type`, `policy`, `cel_expr`, `custom_msg`, `custom_url`, `scope`, `scope_value`), sorted by type, identifier and scope so the file diffs cleanly. The Rules tab has an **Export** button; `GET /api/v1/santa/{env}/rules` returns the same rules with their server fields, which the import ignores.
- **Import:** `POST /api/v1/santa/{env}/rules/import` with a JSON list of rules (at most 4 MiB). Each rule is classified after normalization:
  - **new**: no rule with the same type, identifier and scope exists;
  - **duplicate**: an identical rule exists, or appears earlier in the file; skipped;
  - **conflict**: a rule with the same type, identifier and scope exists with a different policy, message, URL or CEL expression;
  - **invalid**: the rule fails the same validation as a single create.
- With `?dry_run=true` the report is returned and nothing is stored. Without it the new rules are stored in one transaction, but only when no rule is conflicting or invalid: one bad rule blocks the whole import (`applied: false`), and existing rules are never changed. Resolve a conflict by editing the file or the existing rule.
- Re-importing an export is a no-op. An applied import writes one audit line with the counts.
- The Rules tab **Import** button runs the dry run first and shows the report before anything is stored.

From the CLI, in API or DB mode:

```sh
osctrl-cli santa rules-export -e ENV -f rules.json
osctrl-cli santa rules-import -e ENV -f rules.json --dry-run
osctrl-cli santa rules-import -e ENV -f rules.json
```

`rules-import` exits non-zero when a rule is conflicting or invalid, dry run included, so the dry run can gate a review pipeline. In DB mode the first `santa` command creates the Santa tables if they do not exist yet.

### Client mode overrides

The environment sets the default client mode (MONITOR or LOCKDOWN). A tag or a single node can be given a different mode:

- `PUT /api/v1/santa/{env}/modes` with `scope` (`tag` or `node`), `scope_value` (tag name or node UUID) and `client_mode`. Setting the same tag or node again replaces its mode.
- `GET /api/v1/santa/{env}/modes` lists the overrides and `DELETE /api/v1/santa/{env}/modes/{id}` removes one.

At preflight the node gets the most specific mode: a node override wins over a tag override, which wins over the environment mode. If the node has several tags with different modes, LOCKDOWN wins. A change takes effect on the client's next sync; it does not force a clean rule sync, because the mode is not part of the rule digest.

Each machine records the mode osctrl sent at its last preflight (`assigned_mode`) and where it came from (`mode_source`: `env`, `tag` or `node`). The Machines tab shows both. Settings tab: **Mode overrides**.

### Removable media

Each environment sets a removable media policy, sent at every preflight as `removable_media_policy`:

- `ALLOW` (default): mounts are not touched.
- `BLOCK`: mounts are denied.
- `REMOUNT`: mounts that do not already use the chosen options are denied, then remounted with them. Options: `rdonly`, `noexec`, `nosuid`, `nodev`, `nobrowse`, `noowners`, `async`, `-j` (the UI offers the first six).

An optional override for encrypted volumes (`encrypted_removable_media_policy`) takes the same values; when unset, encrypted volumes follow the main policy. Settings tab: **Removable media** and **Encrypted removable media**.

Santa clients that predate `removable_media_policy` read the deprecated `block_usb_mount` and `remount_usb_mode`, which osctrl still sends, derived from the main policy. Those clients ignore the encrypted override. Configs saved before this setting existed are migrated at startup: `block_usb_mount: true` becomes `BLOCK`, otherwise `ALLOW`. The API still accepts `block_usb_mount` when `removable_media` is omitted.

## Authentication model

- Each environment has one token, sent by Santa in the header `X-Osctrl-Santa-Token`. Only its SHA-256 is stored and it is compared in constant time. Generate or rotate it with `POST /api/v1/santa/{env}/token` (environment admin); the plaintext is returned once (`Cache-Control: no-store`) and the old token stops working immediately. Reading the config never returns the token.
- The machine ID in the URL must be a UUID of a node already enrolled in osquery in that same environment. A malformed (non-UUID) machine ID gets `400`. Unknown or other-environment machines get `403`, as do unknown environments and wrong tokens (no existence oracle).
- If the effective rule set changes mid-sync, `ruledownload` returns `409` and the client retries on its next sync.
- Requests are not IP rate limited (that would throttle fleets behind one NAT). Failed authentications are written to the audit log, capped at 60 per hour per environment; drops are counted in the Prometheus metric `santa_auth_audit_dropped_total`.
- Bodies: JSON or protobuf, optionally gzip or zlib compressed; the raw body is capped at 10 MiB and the decompressed body at 20 MiB (`413` past either limit). Responses use the request's encoding.
- Management routes require environment admin permission and write an audit line (`santa: <action>`). Creating a duplicate rule returns `409`.
- Rules are edited in place with `PUT /api/v1/santa/{env}/rules/{id}`. It applies the same validation as create, returns `409` if the edit duplicates another rule and `404` for a rule in another environment. `created_by` is kept, and the audit line records the rule before and after. An edit changes the rule digest, so clients get a clean sync on their next sync.

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

Leave `MachineIDKey` unset so the machine ID is the hardware UUID, which must match the osquery node UUID. The trailing slash on `SyncBaseURL` is required. Leave `ClientMode` unset as well, so the mode chosen in osctrl applies.

## Rolling out to a Mac

### osctrl side

1. Set `santaEnabled: true` on both `osctrl-tls` and `osctrl-api` and restart them.
2. Enroll the Mac in osquery in the target environment. Santa syncs only as an existing node in that environment.
3. In the UI, open the environment's **Santa** page, then **Settings**:
   - set the mode to **MONITOR** to start, which logs what would be blocked without blocking anything;
   - click **Rotate token** and copy the token, which is shown only once;
   - copy the `SyncBaseURL` shown under client setup.

### Mac side (through MDM)

1. Install the Santa package from [North Pole Security's releases](https://github.com/northpolesec/santa/releases).
2. Deploy the profiles that pre-approve Santa, so the user is not prompted and Santa can start:
   - a system extension policy allowing Santa's Endpoint Security extension;
   - a PPPC (TCC) profile granting Full Disk Access to the Santa daemon;
   - optionally, notification settings for the Santa GUI.

   Take the team ID and bundle identifiers from Santa's documentation and sample profiles.
3. Deploy the configuration profile above with this environment's `SyncBaseURL` and token.
4. Make sure the Mac trusts the certificate served by `osctrl-tls`. If it is issued by a private CA, deploy that CA with MDM, or pin it with Santa's server authentication keys.

### Verify

- On the Mac, run `santactl sync` and then `santactl status`.
- In osctrl, the Mac appears under **Santa > Machines** with a last sync time.
- Optionally enable the `santa_agent` posture check. It reports whether the Santa system extension is active on each macOS node.

### Move to enforcement

1. Run in MONITOR mode, review **Events**, and use **Allow** for legitimate binaries. Allowing by TEAMID covers a whole vendor and needs far fewer rules than allowing each binary hash.
2. Use tag- or node-scoped rules for exceptions.
3. Pilot enforcement on a few Macs first: under **Settings > Mode overrides**, set **LOCKDOWN** for a tag (or a single node) while the environment stays in MONITOR.
4. When no new legitimate binaries show up in **Events**, switch the environment to **LOCKDOWN** and remove the pilot override.

## Not implemented

The `commands`, `metrics` and `signalupload` stages; FCM/NATS push; file-access, network-flow and telemetry rules; bundle uploads; MCP tools.
