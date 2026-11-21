# pkg/santa

Optional Santa (North Pole Security, macOS) sync server. Disabled by default; enable with `--santa-enabled` (env `SERVICE_SANTA_ENABLED`, YAML `service.santaEnabled`) on both `osctrl-tls` and `osctrl-api`. Requires a restart. When off, no tables are migrated, no TLS or API routes are registered and `/api/v1/features` reports `santa: false`.

Tables (`santa_env_configs`, `santa_rules`, `santa_mode_overrides`, `santa_machines`, `santa_events`, `santa_binary_machines` and the others below) are migrated only when `santa.NewManager` is constructed.

## Data flow

- `osctrl-tls` serves the stable Santa sync protocol (v1, `santa.sync.v1`): `POST /{env}/santa/sync/{stage}/{machineid}` with `stage` one of `preflight`, `eventupload`, `ruledownload`, `postflight`. `{env}` is the environment UUID, `{machineid}` the node UUID.
- `osctrl-api` manages configuration, the token, rules, and read views of machines and events under `/api/v1/santa/{env}/...` (`config`, `token`, `rules`, `modes`, `machines`, `events`). The React UI (Santa page) calls these. JSON is snake_case.
- Both share the SQL database. Rules are scoped to the environment, a tag, or a node. For each (rule type, identifier) the most specific scope wins (node over tag over environment).

### Digest-based clean sync

At preflight osctrl computes the node's effective rules and an order-independent SHA-256 digest of their synced fields. The digest is stored on the machine as `pending_digest`. If it differs from the `applied_digest` (or the client asked for a clean sync) osctrl answers `CLEAN_RULES`, and the client downloads the full set (500 rules per `ruledownload` page); otherwise `NORMAL`. At postflight `pending_digest` becomes `applied_digest`. The preflight digest is the one stored, so rule or tag changes between preflight and postflight are picked up by the next sync rather than being recorded as applied.

Events uploaded by clients are stored in `santa_events` (fields truncated to 255 characters). Retention is fixed at 30 days; `osctrl-api` prunes daily. The **Events** tab and `GET /api/v1/santa/{env}/events` filter by machine (`machine_id`), decision name or prefix (`decision=BLOCK`) and file hash (`sha256`).

### Events in log sinks and alert rules

After an upload is stored, `osctrl-tls` forwards its execution events and its file access events to the log sinks and the alert rules. Both are optional and need no Santa-specific setting.

- **Log sinks:** each upload is sent as one JSON array of events under the category `santa` (the same fields as `GET /api/v1/santa/{env}/events`). A sink with no category filter receives it; a filtered sink needs `santa` in its categories. File access events go the same way under the category `santa.file_access` (the fields of `GET /api/v1/santa/{env}/file-access-events`). The DB sink ignores both, since the events are already stored. If a sink fails, the error is logged and the upload still succeeds, because the events are stored and a retry would store them twice.
- **Alert rules:** rules with the source `santa_event` match on the event fields `decision`, `file_sha256`, `file_path`, `file_name`, `executing_user`, `team_id`, `signing_id`, `cd_hash`, `bundle_id`, `bundle_name`, `bundle_version`, `bundle_path`, `bundle_hash`, and the leaf certificate of the signing chain: `cert_sha256`, `cert_cn`, `cert_org` and `cert_ou`. They use the usual substring or regex pattern, on one field or on any. For example, field `decision` with pattern `BLOCK` alerts on every blocked execution. A rule alerts once per node and file hash within its cooldown.
- Rules with the source `santa_file_access` match file access events on `decision`, `target` (the accessed path), `rule_name`, `rule_version` and the accessing process: `process_path`, `process_sha256`, `process_signing_id`, `process_team_id` and `process_cd_hash`. For example, field `target` with pattern `/.ssh/` alerts on access to SSH keys. A rule alerts once per node and path (its first 64 bytes) within its cooldown. Execution rules never see file access events, and the other way round. These rules need the same permission as log-content rules (superuser or full query tier), and `osctrl-tls` needs `--alerts-enabled`.
- Event fields are written by the Santa client and are untrusted. The notification detail is one line (`DECISION path sha256=... user=...`) with control characters removed and at most 1024 bytes.
- The osquery log endpoint rejects the log type `santa`, so an osquery node cannot forge Santa events into the sinks.

### Event filters, effective rules and MCP tools

- `GET /api/v1/santa/{env}/events` takes optional filters: `machine_id` (node UUID), `decision` (a decision name or a prefix of one, so `BLOCK` matches every block decision; letters and underscores only, anything else is `400`) and `sha256`.
- `GET /api/v1/santa/{env}/machines/{machineid}/rules` returns the rules a node gets after scope resolution, with its client mode and where the mode comes from. The node must be enrolled in the environment; it does not need to have synced yet.
- The MCP server has four read tools (`list_santa_rules`, `list_santa_machines`, `list_santa_events`, `get_santa_node_rules`) and, behind the MCP write opt-in, `create_santa_rule` and `delete_santa_rule`. They call the routes above, so they need environment admin and write the same audit lines. See [MCP.md](../../MCP.md).

### Binary details

Deciding on a rule needs context, so each file hash has a detail view: the file name in **Events** and in the approval queue opens it.

- `GET /api/v1/santa/{env}/binaries/{sha256}` (environment admin) returns what osctrl knows about the file: name, path, team ID, signing ID, CDHash, bundle (ID, name, version, path) and signing chain from its newest kept event; first and last seen; the number of kept events and blocks; the number of distinct machines and the 100 that reported it most recently (`machine_list`, with hostname, first and last seen and event count); and every rule of the environment that names the file, its team ID, signing ID, CDHash or leaf certificate, whatever its scope. `404` when osctrl never received an event of the hash in the environment.
- Events now keep `bundle_name`, `bundle_version`, `bundle_path` and `signing_chain` (leaf first, at most 8 certificates) from `eventupload`. They are also in the event list and the log sinks; the MCP event tool keeps its own shorter field list. Events stored before this have them empty; no client change is needed.
- **History beyond retention.** Every event upload also updates `santa_binary_machines`: one row per environment, file and machine, with first and last seen and an event count. It is not pruned, so first seen, last seen, the machine count and the machine list survive the 30-day event pruning; after it, the identity fields and the event and block counts are empty, and only a rule on the file's hash still matches. First and last seen are when osctrl received the events, not the client's clock, so a client cannot backdate them. Bundle listings (`BUNDLE_BINARY`) are not executions and are left out. When the table is created, it is filled once from the events still kept.
- All of it is written by Santa clients and is untrusted: a compromised client can report any name, signer or chain for a hash. The view is context for a decision, not proof of who signed the file.

### Retrieving a binary

**Retrieve file** on an event, or in the binary details (from the machine that last ran it), starts an osquery file carve of the event's path on that machine.

- `POST /api/v1/santa/{env}/events/{id}/carve` (environment admin) dispatches to the carves endpoint, so carve access, sensitive paths, node scope, storage and the carve audit line all apply as for any carve. The carve name is kept on the event (`carve_name`) and the Santa audit line names it; the event row then shows the carve status and links to it. The file comes back through the existing osquery carve upload; `osctrl-tls` has no new upload path.
- The machine must be an osquery node of the same environment (Santa machine ID = osquery UUID), else `409`. The path is the event's `file_path` joined with `file_name`, both written by the Santa client: a compromised client can point the carve at another file, which the sensitive-path list still guards.
- The carve is recorded on the event, which is pruned after 30 days; the carve itself follows the carves' own lifecycle.

### Risk checks

Before a vote or an approval allows a file, `osctrl-api` can ask reputation services about its hash. Off until a check is configured on `osctrl-api` (not `osctrl-tls`):

| Setting | Flag / environment | Default |
|---|---|---|
| VirusTotal API key | `--santa-virustotal-key` / `SANTA_VIRUSTOTAL_KEY` | off |
| Engines that must flag a file | `--santa-virustotal-threshold` / `SANTA_VIRUSTOTAL_THRESHOLD` | 3 |
| Custom webhook URL | `--santa-risk-webhook-url` / `SANTA_RISK_WEBHOOK_URL` | off |
| Webhook HMAC secret | `--santa-risk-webhook-secret` / `SANTA_RISK_WEBHOOK_SECRET` | none |
| Verdict cache | `--santa-risk-ttl-hours` / `SANTA_RISK_TTL_HOURS` | 24 |
| Timeout per check | `--santa-risk-timeout-seconds` / `SANTA_RISK_TIMEOUT_SECONDS` | 10 |

- **Secrets.** The key, the webhook URL and its secret come from the environment, flags or the YAML file only. They are never stored in `service_config`, never returned by the API and never logged (request errors drop the URL). Prefer the environment: a flag value shows in the process list.
- **Only hashes are sent.** VirusTotal gets `GET /api/v3/files/{sha256}`. The webhook gets `POST {"sha256": "..."}`, signed with `X-Osctrl-Signature` (HMAC-SHA256, hex) when a secret is set, and must answer `{"verdict": "clean" | "flagged" | "unknown", "detail": "..."}`. The webhook is configured by the operator, not through the API, so private addresses are allowed.
- **Verdicts.** VirusTotal reports `flagged` when at least the threshold of engines call the file malicious, `unknown` when it has never seen the file. Each check's verdict is cached per hash; a check that fails (timeout, quota, bad answer) is cached as `error` for 5 minutes. The overall verdict is `flagged` if any check flags the file, else `error` if any failed, else `clean` or `unknown`.
- **Votes fail closed.** A vote for a flagged file is refused (`409`), and so is one while a check cannot answer (`503`). `unknown` is not an outage and does not stop a vote.
- **Approvals.** Approving a flagged file is refused (`409`) unless the approver sets `override` and gives a reason. The request records it (`risk_override`) and the audit line ends with `override_risk=flagged`. A failed check does not stop an approver; the queue shows it. Denials and MONITOR requests run no check.
- **Where verdicts show.** A new request is checked in the background. The approval queue, the approve/deny link page and the binary details show the cached verdict; the binary details have a **Check now** button (`POST /api/v1/santa/{env}/binaries/{sha256}/risk`, environment admin, audited). The requester never sees a verdict.
- Expired verdicts are pruned daily. VirusTotal's free tier allows 4 lookups a minute and 500 a day; the cache keeps a busy queue within that only if the TTL is long enough.

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

**Temporary MONITOR mode.** A machine can leave LOCKDOWN for 1 to 24 hours and go back on its own. **Longest temporary MONITOR** (`max_monitor_hours`, 0 is 24) lowers the maximum for the environment; grants, requests and extensions above it are refused (`400`). It is a node override with an expiry (`expires_at`), sent as the v1 `client_mode` at preflight; Santa's own temporary monitor mode is v2-only and not used.

- An environment admin grants it with `PUT /api/v1/santa/{env}/modes` and `hours` (scope `node`, `MONITOR` only), or with a duration in **Settings > Mode overrides**. A user asks for it from the request page (`POST /api/v1/santa/{env}/requests` with `kind: "monitor"` and `hours`); it goes through the approval queue and notifications like a file request, and the hours count from the approval.
- The machine must have synced with the environment. A grant replaces a temporary override of the machine, never a permanent one (`409`): change or delete that instead. Setting a permanent override replaces a temporary one.
- Expiry is server-side and needs nobody: from `expires_at` the override no longer applies or appears in the list. `osctrl-api` removes expired overrides every minute and writes each expiry to the audit log; the grant, the request and the approval are audited too.
- **End now** (`DELETE /api/v1/santa/{env}/modes/{id}`) removes the override; the audit line is `end temporary MONITOR`, and the requester, if any, is told it ended. **Extend** (`POST /api/v1/santa/{env}/modes/{id}/extend` with `hours`) adds hours to the expiry, which can then be at most the maximum from now. Both are in **Settings > Mode overrides**, and extending is audited (`extend temporary MONITOR`).
- The machine switches at its next preflight and goes back at its first preflight after the expiry, so both changes wait for the client's sync interval (see [Sync interval](#sync-interval)). A machine that does not sync stays in MONITOR until it does.

### Sync interval

Rule and setting changes reach a machine at its next full sync. `full_sync_interval_seconds` (**Settings → Sync interval**) is sent at every preflight and takes effect from the following sync:

- `0` (default) leaves Santa's own interval, 600 seconds.
- Otherwise 60 to 86400 seconds. Each full sync is three or four requests per machine (preflight, ruledownload, postflight, and eventupload when there are events), so load scales with machines ÷ interval: 1,000 Macs at 60 seconds is 50 to 67 requests a second, against 5 to 7 at the default.

There is no push. v1's `push_token` only works with a token chain signed by North Pole Security, and NATS push is v2-only, so a third-party server like osctrl cannot wake a client; a shorter interval is the only lever. Santa's other v2-only features (network-flow rules and the network extension, file access rule delivery, telemetry signal rules, Santa-side mode transitions, package rules) are out of scope for the same reason: the client enables v2 only for Workshop domains or an NPS-signed token.

### IdP group tags

Tag-scoped rules and mode overrides can follow department membership. **Settings → IdP group tags** maps IdP groups to existing tags of the environment (`group_tags` in the config, at most 100); at each preflight the machine gets the tags of its primary user's groups and loses the ones it no longer qualifies for, before rules and mode are computed.

- **Groups come from SSO login or SCIM.** Each OIDC or SAML login stores the user's groups from the provider's groups claim or attribute (`santa_user_groups`); a provider without one configured stores nothing and keeps what was there. With SSO alone, a user who has never signed in to osctrl has no groups, and a change at the IdP reaches osctrl at their next login. With [SCIM provisioning](../../docs/auth-providers.md#scim-provisioning) the IdP pushes changes as they happen, with no login; once SCIM manages a user, SSO logins no longer change their groups, and a user that is deactivated or deleted has none. Either way the machine picks them up at its next sync. **Users → user → Groups…** shows what is stored and where it came from. Map tags to the group's display name as the IdP sends it.
- **Matching** compares the Santa `primary_user` with osctrl users (for SCIM users, the account named from their `userName`), ignoring case. **Settings → Match the primary user to** (`group_match`) picks how:
  - *osctrl username* (`""`, the default): the whole username. `jdoe` matches `JDoe`, not `jdoe@example.com`.
  - *Username before @* (`local_part`): the part before `@` on both sides, so the Mac account `jdoe` matches `jdoe@example.com`.
  - *Account email* (`email`): the email of the osctrl account, so `jdoe@example.com` matches the account `jdoe` whose email it is.

  A primary user matching more than one osctrl user gets no group tags, and a warning naming the matches is logged. With `local_part` that happens when two IdP domains share a name (`jdoe@example.com` and `jdoe@corp.example`): neither user's Macs are tagged until one account is removed. It also widens what a forged `primary_user` (see Trust) can reach: any user with that local part.
- **Only tags the mapping added are removed** (`tagged_by` = `santa:idp-groups`); a tag set by hand stays even when the user leaves the group. A mapped tag that was deleted is not recreated, and the config rejects tags that do not exist in the environment.
- **Trust.** `primary_user` is reported by the client. A host holding the environment token can claim any user and get that user's group tags, so map groups to tags that loosen rules (allow rules, MONITOR overrides) only where that is acceptable, and prefer mapping groups to tags that tighten them.
- **SCIM token.** It can change any user's groups, and so their machines' group tags; see the trust note above about mapping groups to tags that loosen rules.

### Second admin approval

With **Settings → Require a second admin** (`require_second_admin`), one compromised admin cannot switch enforcement off alone. These actions are held instead of applied:

- switching the environment to MONITOR, or a new `allowed_path_regex` (config PUT);
- turning `require_second_admin` off (turning it on is immediate);
- any MONITOR mode override, permanent or temporary, for a tag or a machine, and extending a temporary one;
- creating an environment-wide rule that can allow (`ALLOWLIST`, `ALLOWLIST_COMPILER`, `CEL`), changing a rule into one or changing what it allows, and a rules import that contains one (not a dry run);
- rotating the sync token.

A held action answers `202` with the pending change and leaves everything as it was. It appears in **Santa → Changes** (`GET /api/v1/changes/{env}`), where another admin of the environment approves or denies it (`POST /api/v1/changes/{env}/{id}/decision`). The requester can deny their own change to withdraw it but cannot approve it. Once approved, the requester applies it with **Apply**, or by sending the exact same request again (same method, path and body). The handler then runs as usual, with its own validation, and the approval is used up. A change expires 24 hours after it was requested, approved or not. The request, the decision and the apply are each in the audit log (`change: request|approve|deny|apply`), and the apply line names the approver.

With the setting on, an admin also cannot approve their own approval request for MONITOR or with scope `env`.

Not held: deleting rules or LOCKDOWN overrides, other config settings, rules created by votes (the vote threshold is its own multi-party check), and approving someone else's request. A second account under the same person's control defeats the check; it is meant for separate people.

The mechanism is `pkg/changes` and is not Santa-specific: another feature can hold its actions by calling `secondAdmin` in its handler.

### Removable media

Each environment sets a removable media policy, sent at every preflight as `removable_media_policy`:

- `ALLOW` (default): mounts are not touched.
- `BLOCK`: mounts are denied.
- `REMOUNT`: mounts that do not already use the chosen options are denied, then remounted with them. Options: `rdonly`, `noexec`, `nosuid`, `nodev`, `nobrowse`, `noowners`, `async`, `-j` (the UI offers the first six).

An optional override for encrypted volumes (`encrypted_removable_media_policy`) takes the same values; when unset, encrypted volumes follow the main policy. Settings tab: **Removable media** and **Encrypted removable media**.

Santa clients that predate `removable_media_policy` read the deprecated `block_usb_mount` and `remount_usb_mode`, which osctrl still sends, derived from the main policy. Those clients ignore the encrypted override. Configs saved before this setting existed are migrated at startup: `block_usb_mount: true` becomes `BLOCK`, otherwise `ALLOW`. The API still accepts `block_usb_mount` when `removable_media` is omitted.

### File access rules

Santa can restrict which processes read or write sensitive files, such as browser cookies, keychains or SSH keys. The v1 sync protocol cannot deliver these rules, so deploy them with MDM (see [Deploying file access rules](#deploying-file-access-rules)). osctrl does two things with them:

- It stores the violations that clients upload in `file_access_events`: the rule name and version, the accessed path, the decision (`DENIED`, `DENIED_INVALID_SIGNATURE` or `AUDIT_ONLY`), and the process chain (accessing process first, at most 8 processes). They appear in the **File access** tab and through `GET /api/v1/santa/{env}/file-access-events` (environment admin), filtered by `machine_id`, a substring of the path (`target`) or of any process path in the chain (`process`), both without case, and the exact `decision`. They are pruned with the execution events after 30 days, and forwarded to log sinks and alert rules (see [Events in log sinks and alert rules](#events-in-log-sinks-and-alert-rules)). Every field is written by the client.
- It sends `override_file_access_action` at preflight, set per environment under **Settings > File access rules override**:
  - unset (default): nothing is sent, and each client keeps its current setting;
  - `NONE`: the rules apply as written;
  - `AUDIT_ONLY`: violations are logged and uploaded, but allowed;
  - `DISABLE`: the rules are not enforced.

  Clients pick up a change at their next sync. Choosing unset again does not undo an override a client already received; choose `NONE` to undo it.

### Upload and path settings

These preflight settings live under **Settings** (and the config API). osctrl sends all of them at every preflight, so turning one off reaches clients at their next sync.

- **Bundles** (`enable_bundles`): when Santa blocks a binary inside an app bundle, it hashes the whole bundle and uploads that hash with the event. The first time osctrl sees a bundle hash in an environment, it answers with `event_upload_bundle_binaries`, and the client uploads every binary of the bundle as a `BUNDLE_BINARY` event. These appear in **Events** with the bundle's `bundle_hash`; create rules for them from there. osctrl stops asking for a bundle once one of its `BUNDLE_BINARY` events is stored. Bundle hashes that are not 64 hex characters are ignored.
- **Upload all execution events** (`enable_all_event_upload`): clients upload every execution Santa decides on, not only blocks and would-be blocks. This can be a lot of events.
- **Skip would-be blocks** (`disable_unknown_event_upload`): clients do not upload executions that LOCKDOWN would block, which is the bulk of MONITOR mode events.
- **Allowed and blocked path regexes** (`allowed_path_regex`, `blocked_path_regex`): an execution that matches no rule is allowed or blocked when its path matches. The blocked regex is checked first. Santa uses ICU regexes; osctrl checks them with Go's RE2 parser, so use the common subset (no lookaround or backreferences). At most 1024 characters, one line. Empty turns it off. These are much easier to get wrong than rules: a writable path in the allowed regex lets anyone run anything from it.
- **Block dialog URL and button label** (`event_detail_url`, `event_detail_text`): the button in the Santa block dialog. The URL must be `https` and can use Santa placeholders such as `%file_sha%`, `%machine_id%`, `%username%` and `%bundle_or_file_identifier%`. It overrides the approval request link below. The label is at most 32 characters; when empty, the approval link keeps **Request approval** and a custom URL keeps the client's default. When neither the URL nor the approval URL is set, osctrl sends nothing, and clients keep what they had.

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

**Deciding requests.** Environment admins and approvers (below) decide requests in the **Requests** tab of the Santa page. It lists pending requests first, with the file name, path, hash and signing ID from the blocked event, the machine, the user who ran the file, the requester and the justification. The list can be searched, filtered by status, and decided one request at a time or several at once. The API is `GET /api/v1/santa/{env}/requests` (optional `status`, newest 500) and `POST /api/v1/santa/{env}/requests/{id}/decision`:

```json
{ "decision": "approve", "scope": "node", "scope_value": "", "reason": "" }
```

- `approve` creates one `BINARY` `ALLOWLIST` rule for the file hash, in the scope the approver picks: `node` (the machine that asked), `tag` (`scope_value` is the tag name) or `env`. The rule and the status change are stored together, and machines in that scope get the rule on their next sync.
- An environment admin can pick a broader rule with `rule_type`, so later versions or other files run without new requests. The identifier always comes from the request and its blocked event, never from the body: `SIGNINGID` (the file's signing ID, as `TEAMID:signing.id` or `platform:signing.id`), `TEAMID` (everything the developer signs) or `CERTIFICATE` (the leaf certificate the client reported). A file without that identifier answers `400`. The request records the type (`rule_type`).
- An environment admin can also set `bundle` (with `BINARY`) to allow, in the same scope and transaction, every binary the client uploaded for the file's bundle (needs **Enable bundles**, at most 500). Uploaded hashes that are not SHA-256 are skipped. Only the blocked file runs through the risk checks.
- Approvers get `403` for either; they approve the file's hash only. In the queue the choices appear when an admin decides one request. Notification links and Slack buttons always create a hash rule.
- If an allow rule for the same identifier and scope already exists, the request is approved and points at that rule; no second rule is created.
- If the existing rule for the same hash and scope blocks the file, the answer is `409` and the request stays pending. Change or delete that rule first.
- `deny` needs a `reason` (at most 1000 characters). A reason is optional on approval.
- A request that was already decided or has expired answers `409`.
- The requester sees the new status, and the reason, in their list on the request page.
- Every decision writes an audit line with the request, hash, machine, requester and, for approvals, the rule ID, rule type, scope and `bundle=true` when the bundle was allowed. The reason text is kept on the request, not in the audit line.
- Deleting the rule later does not change the request; it stays `approved` with the old rule ID.
- Bulk decisions in the UI are one API call per request, so a failure on one does not undo the others.

**Approvers.** A team such as IT helpdesk can decide requests without being environment admins. In **Settings → Approvers**, list osctrl users (`approver_users`, matched in any case) and IdP groups (`approver_groups`, matched exactly against the groups stored from SCIM or the user's last SSO login), at most 100 each. Each listed user must exist.

- Approvers see the Santa page with the **Requests** tab only, and can use notification links. `GET /api/v1/santa/{env}/access` tells the UI whether the caller is an admin or an approver.
- They can list and read requests, and approve or deny them with any scope, like an admin. They cannot override a flagged risk check (`403`), cannot approve their own request, and get `403` from every other Santa route: rules, settings, token, events, machines and binary details. The queue shows them machine IDs instead of host names.
- Group membership is checked on every call, so removing someone from the group in the IdP takes effect at their next SCIM update or SSO login.
- Adding approvers widens who can allow files, so with **Require a second admin** it is held like the other weakening changes. Removing approvers is not.

**Notifying approvers.** Approvers do not have to watch the queue: each new request can be sent to alert channels (email, webhook or Slack). It needs alerts enabled in `osctrl-api` (`--alerts-enabled`) and the approval URL set.

- In **Settings**, tick the channels under **Notify about new requests** (`notify_channels` in the config API, at most 10). A channel must be global or belong to the environment.
- Changing the channels requires a superuser, like alert rules on log content: the notification carries text written by the requester and by the Santa client. An environment admin can still save the rest of the config; the channels are kept.
- The notification is sent by `osctrl-api` when the request is created, once per request. A request merged into a pending one sends nothing. A notification that cannot be delivered is logged and does not fail the request; it is not retried.
- The message says who asks, for which file and machine, and why, on one line, followed by an **Approve** and a **Deny** link:

```
https://osctrl.example.com/santa/decide/ENVIRONMENT-UUID?request=12&action=approve#TOKEN
```

- Opening a link decides nothing. It shows the request and the same choices as the queue (scope for an approval, reason for a denial); the approver confirms there. The page asks them to sign in first.
- A link is not a credential. `POST /api/v1/santa/{env}/requests/link` requires an environment admin or approver session like every other decision, and the token only proves the link came from the notification. Anyone else who gets the link can do nothing with it.
- A link works once, for the action it was made for, for 72 hours. A used, expired, unknown or other-environment link, or an approve link used to deny, answers `410`. Once the request is decided the other link answers `409`. A decision that fails (for example a block rule in the way) leaves the link usable.
- Only the SHA-256 of each token is stored. The token is the URL fragment, so the browser does not send it with the page request; it is posted in the request body. The alert history keeps the message without the links.

**Deciding in Slack.** A Slack alert channel posts each new request with **Approve (this machine)** and **Deny** buttons, so an approver can decide without leaving Slack.

- Create a Slack app with a bot token (`chat:write`, and `users:read.email` to identify who clicks), invite the bot to the channel, and add a **Slack** alert channel with the token, the channel ID and the app's signing secret. Without the signing secret the messages have no buttons.
- In the app's **Interactivity** settings, set the request URL to `https://<osctrl-api>/api/v1/slack/interact/<alert channel ID>`. Slack must be able to reach `osctrl-api`.
- Tick the channel under **Notify about new requests** like any other channel. A button only works for an environment that notifies that channel.
- Every callback must carry a valid signature from the signing secret and a timestamp at most 5 minutes old, or it is refused with `401`. Each button carries the token of the matching link, so it works once: a replayed callback finds the link used.
- The Slack user is identified by the email Slack has confirmed for their account (`users.info`), which must match the email of exactly one osctrl account (any case), not a service account. That user must be an environment admin or approver. Anyone else, or an unmatched Slack user, gets a note only they can see, and nothing is decided.
- **Approve** allows the file on the requester's machine (scope `node`), or grants the MONITOR request. **Deny** uses the reason "Denied in Slack". For another scope, a risk override (a flagged file cannot be approved from Slack) or a written reason, use the links in the message.
- The decision is audited like any other, with ` via Slack`, and the message is replaced with the outcome, without buttons. Slack sessions are not osctrl sessions: osctrl MFA does not apply, so use Slack's own sign-in policies.

**Notifying requesters.** Requesters can be emailed when their request is decided. It is off until an environment admin picks an email channel under **Email requesters** in **Settings** (`requester_channel` in the config API; 0 turns it off). The channel must be an email channel that is global or belongs to the environment.

- Only the channel's SMTP relay and sender are used. The email goes to the requester's osctrl account address, never to the channel's recipients. A requester without an email address gets nothing.
- The requester is told when the request is approved or denied, by whom and with the reason given. An approved MONITOR request says when the window ends, and a second email is sent when it ends (within a minute of the expiry). A MONITOR override an admin grants directly has no requester and sends nothing.
- Like approver notifications, a failed email is logged and not retried, and it never fails the decision. These emails are not written to the alert history; the decision is in the audit log.

**Voting.** For software many people use, votes can allow a file without an approver. It is off until an environment admin sets a threshold in **Settings** (`vote_local_threshold` and `vote_global_threshold` in the config API; 0 turns one off, the global one cannot be below the local one, both need the approval URL).

- The request page shows the vote count and a **Vote to allow** button next to the request form. Any signed-in account can vote (`POST /api/v1/santa/{env}/votes`), under the same condition as a request: the machine must have reported the block. One vote per account and file; voting again changes nothing. The page shows counts, never who voted, and lets a voter withdraw their vote (`DELETE /api/v1/santa/{env}/votes?sha256=...`). Rules the votes already created stay.
- At the **local threshold** every machine that voted gets a node-scoped `BINARY` allow rule, and each later voter's machine gets one as they vote. At the **global threshold** the file gets one environment-scoped allow rule. Rules made by votes have `votes` as their creator, and each one is written to the audit log with the vote that caused it.
- Known-bad files cannot be voted for (`409`): Santa must have blocked the file as unknown (`BLOCK_UNKNOWN`), and no rule other than an allow rule may name the file, its team ID, signing ID or CDHash in any scope of the environment. To stop a vote, add a block rule. A file with a denied request cannot be voted for either (`409`): votes do not overrule an approver.
- A threshold of 1 lets every user allow what they run; choose thresholds with the number of accounts in mind. Accounts are the unit: someone with several accounts has several votes.
- Environment admins see who voted, from which machine and when, in the binary details of the Requests tab (`GET /api/v1/santa/{env}/votes/{sha256}`).
- Votes are kept until **Days until votes expire** (`vote_expiry_days`, at most 3650; 0 keeps them): `osctrl-api` deletes older votes once a day. Rules the votes created stay.
- Deleting a rule made by votes also deletes the file's votes, so the count starts again and one new vote does not bring the rule back. The audit line says how many went (`votes_cleared`).
- Lowering a threshold takes effect at the next vote for a file.

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

### Deploying file access rules

Add the policy inline under `FileAccessPolicy` in the same payload, or put it in a separate plist and point `FileAccessPolicyPlist` at that file. Santa re-reads the file every `FileAccessPolicyUpdateIntervalSec` seconds (10 minutes by default). For example, this policy lets only Chrome read its cookies:

```xml
<key>FileAccessPolicy</key>
<dict>
    <key>Version</key>
    <string>v1.0</string>
    <key>WatchItems</key>
    <dict>
        <key>ChromeCookies</key>
        <dict>
            <key>Paths</key>
            <array>
                <dict>
                    <key>Path</key>
                    <string>/Users/*/Library/Application Support/Google/Chrome/Default/Cookies</string>
                    <key>IsPrefix</key>
                    <false/>
                </dict>
            </array>
            <key>Options</key>
            <dict>
                <key>RuleType</key>
                <string>PathsWithAllowedProcesses</string>
                <key>AllowReadAccess</key>
                <false/>
                <key>AuditOnly</key>
                <true/>
            </dict>
            <key>Processes</key>
            <array>
                <dict>
                    <key>SigningID</key>
                    <string>com.google.Chrome*</string>
                    <key>TeamID</key>
                    <string>EQHXZ8M8AV</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

The `WatchItems` key (here `ChromeCookies`) is the rule name that osctrl shows, and `Version` is the rule version. `RuleType` also takes `PathsWithDeniedProcesses`, `ProcessesWithAllowedPaths` and `ProcessesWithDeniedPaths`. Start with `AuditOnly`, check the **File access** tab for legitimate access, then remove it. Santa's file access documentation has the full format.

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

The `commands`, `metrics` and `signalupload` stages; FCM/NATS push (see [Sync interval](#sync-interval)); delivering file access rules (a v2-only stage; deploy them with MDM), network-flow, telemetry signal and package rules; Santa-side mode transitions; `export_configuration` (telemetry export to a signed POST URL; no osctrl log sink issues one); one-step rules for a whole bundle.
