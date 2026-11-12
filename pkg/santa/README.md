# pkg/santa

Optional Santa (North Pole Security, macOS) sync server. Disabled by default; enable with `--santa-enabled` (env `SERVICE_SANTA_ENABLED`, YAML `service.santaEnabled`) on both `osctrl-tls` and `osctrl-api`. Requires a restart. When off, no tables are migrated, no TLS or API routes are registered and `/api/v1/features` reports `santa: false`.

Tables (`santa_env_configs`, `santa_rules`, `santa_machines`, `santa_events`) are migrated only when `santa.NewManager` is constructed.

## Data flow

- `osctrl-tls` serves the stable Santa sync protocol (v1, `santa.sync.v1`): `POST /{env}/santa/sync/{stage}/{machineid}` with `stage` one of `preflight`, `eventupload`, `ruledownload`, `postflight`. `{env}` is the environment UUID, `{machineid}` the node UUID.
- `osctrl-api` manages configuration, the token, rules, and read views of machines and events under `/api/v1/santa/{env}/...` (`config`, `token`, `rules`, `machines`, `events`). The React UI (Santa page) calls these. JSON is snake_case.
- Both share the SQL database. Rules are scoped to the environment, a tag, or a node. For each (rule type, identifier) the most specific scope wins (node over tag over environment).

### Digest-based clean sync

At preflight osctrl computes the node's effective rules and an order-independent SHA-256 digest of their synced fields. The digest is stored on the machine as `pending_digest`. If it differs from the `applied_digest` (or the client asked for a clean sync) osctrl answers `CLEAN_RULES`, and the client downloads the full set (500 rules per `ruledownload` page); otherwise `NORMAL`. At postflight `pending_digest` becomes `applied_digest`. The preflight digest is the one stored, so rule or tag changes between preflight and postflight are picked up by the next sync rather than being recorded as applied.

Events uploaded by clients are stored in `santa_events` (fields truncated to 255 characters). Retention is fixed at 30 days; `osctrl-api` prunes daily.

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
3. When no new legitimate binaries show up in **Events**, switch the environment to **LOCKDOWN**. The mode applies to the whole environment, so a LOCKDOWN pilot group needs its own environment.

## Not implemented

The `commands`, `metrics` and `signalupload` stages; FCM/NATS push; file-access, network-flow and telemetry rules; bundle uploads; forwarding Santa events to alert rules or log sinks; MCP tools.
