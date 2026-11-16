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

### Event filters, effective rules and MCP tools

- `GET /api/v1/santa/{env}/events` takes optional filters: `machine_id` (node UUID), `decision` (a decision name or a prefix of one, so `BLOCK` matches every block decision; letters and underscores only, anything else is `400`) and `sha256`.
- `GET /api/v1/santa/{env}/machines/{machineid}/rules` returns the rules a node gets after scope resolution, with its client mode and where the mode comes from. The node must be enrolled in the environment; it does not need to have synced yet.
- The MCP server has four read tools (`list_santa_rules`, `list_santa_machines`, `list_santa_events`, `get_santa_node_rules`) and, behind the MCP write opt-in, `create_santa_rule` and `delete_santa_rule`. They call the routes above, so they need environment admin and write the same audit lines. See [MCP.md](../../MCP.md).

### Binary details

Deciding on a rule needs context, so each file hash has a detail view: the file name in **Events** and in the approval queue opens it.

- `GET /api/v1/santa/{env}/binaries/{sha256}` (environment admin) returns what the stored events say about the file: name, path, team ID, signing ID, CDHash, bundle (ID, name, version, path) and signing chain from its newest event; first and last seen; the number of events, blocks and distinct machines; and every rule of the environment that names the file, its team ID, signing ID, CDHash or leaf certificate, whatever its scope. `404` when the environment has no event for the hash.
- Events now keep `bundle_name`, `bundle_version`, `bundle_path` and `signing_chain` (leaf first, at most 8 certificates) from `eventupload`. They are also in the event list and the log sinks; the MCP event tool keeps its own shorter field list. Events stored before this have them empty; no client change is needed.
- Everything comes from `santa_events`, which is pruned after 30 days. First seen, last seen and the counts cover that window only, not the file's whole history.
- All of it is written by Santa clients and is untrusted: a compromised client can report any name, signer or chain for a hash. The view is context for a decision, not proof of who signed the file.

### Reports

The **Reports** tab answers when an environment or a machine can move to LOCKDOWN. `GET /api/v1/santa/{env}/reports?days=N` (environment admin, `N` 1 to 30, default 14) computes, from the events received in the window:

- **Ready for lockdown:** every machine assigned MONITOR at its last preflight, with its `ALLOW_UNKNOWN` count, that is, the executions no rule allowed and LOCKDOWN would have blocked. A machine is ready with none and a sync within the window; one that has not synced has reported nothing to judge it by. Ready machines come first. Machines already in LOCKDOWN are left out.
- **Top blocked:** binaries and team IDs ranked by `BLOCK_*` events, with the number of machines (and, for a team ID, of distinct binaries).
- **Rule coverage gaps:** the binaries most executed with no rule deciding them (`ALLOW_UNKNOWN` or `BLOCK_UNKNOWN`), the first candidates for an allow or block rule.

Each ranked list has at most 20 entries. The window is on the time osctrl received each event, not the client's clock, and cannot exceed the 30 days events are kept. A binary name opens the binary details. The queries read one environment's events in the window through the `(environment_id, created_at)` index `idx_santa_events_env_created`, which `osctrl-api` builds in the background at startup (concurrently on PostgreSQL), so a large events table does not hold up startup. All names and team IDs are written by Santa clients.

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

**Temporary MONITOR mode.** A machine can leave LOCKDOWN for 1 to 24 hours and go back on its own. It is a node override with an expiry (`expires_at`), sent as the v1 `client_mode` at preflight; Santa's own temporary monitor mode is v2-only and not used.

- An environment admin grants it with `PUT /api/v1/santa/{env}/modes` and `hours` (scope `node`, `MONITOR` only), or with a duration in **Settings > Mode overrides**. A user asks for it from the request page (`POST /api/v1/santa/{env}/requests` with `kind: "monitor"` and `hours`); it goes through the approval queue and notifications like a file request, and the hours count from the approval.
- The machine must have synced with the environment. A grant replaces a temporary override of the machine, never a permanent one (`409`): change or delete that instead. Setting a permanent override replaces a temporary one.
- Expiry is server-side and needs nobody: from `expires_at` the override no longer applies or appears in the list. `osctrl-api` removes expired overrides every minute and writes each expiry to the audit log; the grant, the request and the approval are audited too.
- The machine switches at its next preflight and goes back at its first preflight after the expiry, so both changes wait for the client's sync interval (`FullSyncInterval`, 10 minutes by default in Santa). A machine that does not sync stays in MONITOR until it does.

### Removable media

Each environment sets a removable media policy, sent at every preflight as `removable_media_policy`:

- `ALLOW` (default): mounts are not touched.
- `BLOCK`: mounts are denied.
- `REMOUNT`: mounts that do not already use the chosen options are denied, then remounted with them. Options: `rdonly`, `noexec`, `nosuid`, `nodev`, `nobrowse`, `noowners`, `async`, `-j` (the UI offers the first six).

An optional override for encrypted volumes (`encrypted_removable_media_policy`) takes the same values; when unset, encrypted volumes follow the main policy. Settings tab: **Removable media** and **Encrypted removable media**.

Santa clients that predate `removable_media_policy` read the deprecated `block_usb_mount` and `remount_usb_mode`, which osctrl still sends, derived from the main policy. Those clients ignore the encrypted override. Configs saved before this setting existed are migrated at startup: `block_usb_mount: true` becomes `BLOCK`, otherwise `ALLOW`. The API still accepts `block_usb_mount` when `removable_media` is omitted.

### Approval requests

A user whose software was blocked can ask for it to be allowed, from the Santa block dialog. It is off by default.

**Turn it on.** In **Settings**, set **Approval request URL** to the address of the osctrl UI, for example `https://osctrl.example.com` (`approval_url` in the config API). It must be an `https` URL without query, fragment or `%` characters; a path prefix is fine. At the next preflight osctrl sends `event_detail_url` and `event_detail_text`, and the block dialog shows a **Request approval** button that opens:

```
https://osctrl.example.com/santa/request/ENVIRONMENT-UUID?sha256=%file_sha%&machine_id=%machine_id%
```

Santa fills the two placeholders. An `EventDetailURL` in the Mac's configuration profile is replaced by the one osctrl sends, and a rule's own custom URL still wins for that rule. Emptying the setting removes the link and turns the request routes off for the environment.

**The request.** The page asks the user to sign in, then for a justification (at most 1000 characters). `POST /api/v1/santa/{env}/requests` stores a `pending` request when osctrl holds a `BLOCK` event for that file on that machine; the file name, path, signing ID, team ID and executing user are copied from the event. Details:

- A pending request for the same file and machine is returned instead of a second one, whoever asks.
- One account can hold 20 pending requests per environment (`429` beyond that).
- If Santa has not uploaded the block yet, the answer is `404` and the user retries a minute later. The same `404` covers an unknown environment and an environment with requests turned off.
- Pending requests older than 30 days become `expired` (same window as event retention).
- `approved` and `denied` are set by an approver, see **Deciding requests** below.

**Who can request.** Any signed-in osctrl account, with no environment permission needed. There is no separate requester role: a requester is an account with no permissions, usually created at first SSO login by a provider with **JIT provision** on, or created by hand. Through these routes a requester gets back only the hash, machine ID, status and date of a request, plus their own justification. `GET /api/v1/santa/{env}/requests/mine` lists only their own requests. The request page sits outside the application shell.

Such an account is still an osctrl account. It can open the rest of the UI, where it sees what any account without permissions sees: an empty environment list, its own profile, and data that needs no environment permission, such as the osquery table schema.

**Limits to know.**

- osctrl does not check that the person signing in is the user of the Mac in the link. Anyone with an account who knows a machine UUID and a file hash blocked on it can file the request. The request records who asked.
- The `404` for a block osctrl has not seen tells a requester whether a given file was blocked on a given machine.
- Two people asking for the same file at the same instant can each get a pending request. Each is decided on its own; approving both for the same scope still leaves one rule.

**Deciding requests.** Environment admins decide requests in the **Requests** tab of the Santa page. It lists pending requests first, with the file name, path, hash and signing ID from the blocked event, the machine, the user who ran the file, the requester and the justification. The list can be searched, filtered by status, and decided one request at a time or several at once. The API is `GET /api/v1/santa/{env}/requests` (optional `status`, newest 500) and `POST /api/v1/santa/{env}/requests/{id}/decision`:

```json
{ "decision": "approve", "scope": "node", "scope_value": "", "reason": "" }
```

- `approve` creates one `BINARY` `ALLOWLIST` rule for the file hash, in the scope the approver picks: `node` (the machine that asked), `tag` (`scope_value` is the tag name) or `env`. The rule and the status change are stored together, and machines in that scope get the rule on their next sync.
- If an allow rule for the same hash and scope already exists, the request is approved and points at that rule; no second rule is created.
- If the existing rule for the same hash and scope blocks the file, the answer is `409` and the request stays pending. Change or delete that rule first.
- `deny` needs a `reason` (at most 1000 characters). A reason is optional on approval.
- A request that was already decided or has expired answers `409`.
- The requester sees the new status, and the reason, in their list on the request page. osctrl does not send an email.
- Every decision writes an audit line with the request, hash, machine, requester and, for approvals, the rule ID and scope. The reason text is kept on the request, not in the audit line.
- Deleting the rule later does not change the request; it stays `approved` with the old rule ID.
- Bulk decisions in the UI are one API call per request, so a failure on one does not undo the others.

**Notifying approvers.** Approvers do not have to watch the queue: each new request can be sent to alert channels (email or webhook). It needs alerts enabled in `osctrl-api` (`--alerts-enabled`) and the approval URL set.

- In **Settings**, tick the channels under **Notify about new requests** (`notify_channels` in the config API, at most 10). A channel must be global or belong to the environment.
- Changing the channels requires a superuser, like alert rules on log content: the notification carries text written by the requester and by the Santa client. An environment admin can still save the rest of the config; the channels are kept.
- The notification is sent by `osctrl-api` when the request is created, once per request. A request merged into a pending one sends nothing. A notification that cannot be delivered is logged and does not fail the request; it is not retried.
- The message says who asks, for which file and machine, and why, on one line, followed by an **Approve** and a **Deny** link:

```
https://osctrl.example.com/santa/decide/ENVIRONMENT-UUID?request=12&action=approve#TOKEN
```

- Opening a link decides nothing. It shows the request and the same choices as the queue (scope for an approval, reason for a denial); the approver confirms there. The page asks them to sign in first.
- A link is not a credential. `POST /api/v1/santa/{env}/requests/link` requires an environment admin session like every other decision, and the token only proves the link came from the notification. Anyone else who gets the link can do nothing with it.
- A link works once, for the action it was made for, for 72 hours. A used, expired, unknown or other-environment link, or an approve link used to deny, answers `410`. Once the request is decided the other link answers `409`. A decision that fails (for example a block rule in the way) leaves the link usable.
- Only the SHA-256 of each token is stored. The token is the URL fragment, so the browser does not send it with the page request; it is posted in the request body. The alert history keeps the message without the links.

**Voting.** For software many people use, votes can allow a file without an approver. It is off until an environment admin sets a threshold in **Settings** (`vote_local_threshold` and `vote_global_threshold` in the config API; 0 turns one off, the global one cannot be below the local one, both need the approval URL).

- The request page shows the vote count and a **Vote to allow** button next to the request form. Any signed-in account can vote (`POST /api/v1/santa/{env}/votes`), under the same condition as a request: the machine must have reported the block. One vote per account and file; voting again changes nothing. The page shows counts, never who voted.
- At the **local threshold** every machine that voted gets a node-scoped `BINARY` allow rule, and each later voter's machine gets one as they vote. At the **global threshold** the file gets one environment-scoped allow rule. Rules made by votes have `votes` as their creator, and each one is written to the audit log with the vote that caused it.
- Known-bad files cannot be voted for (`409`): Santa must have blocked the file as unknown (`BLOCK_UNKNOWN`), and no rule other than an allow rule may name the file, its team ID, signing ID or CDHash in any scope of the environment. To stop a vote, add a block rule. osctrl has no risk scoring yet, so rules are the only signal.
- A threshold of 1 lets every user allow what they run; choose thresholds with the number of accounts in mind. Accounts are the unit: someone with several accounts has several votes.
- Votes are kept. Lowering a threshold takes effect at the next vote for a file, and deleting a rule made by votes does not remove the votes: the next vote creates it again unless a block rule is in the way.
- A webhook channel receives the usual alert JSON with the message in `detail`. Slack and similar tools need a relay that maps it to their format; there are no interactive buttons.

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

The `commands`, `metrics` and `signalupload` stages; FCM/NATS push; file-access, network-flow and telemetry rules; bundle uploads.
