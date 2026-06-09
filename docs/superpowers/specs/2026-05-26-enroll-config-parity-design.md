# Enroll + Config parity with legacy admin

## Context

The new React SPA exposes the per-environment Enrollment page
(`/_app/env/{env}/enroll`) and Configuration page
(`/_app/env/{env}/config`). Both surfaces are functional but missing
controls that the legacy Go-template admin (`cmd/admin`) provides.
Operators migrating to the SPA need those controls or they cannot:

- View, download, or replace the TLS server certificate that
  osquery agents pin against.
- Pull the per-OS flags blob that ships pre-baked
  certificate/secret paths for each platform installer.
- Verify the assembled `osquery.conf` document the agent will receive
  — the SPA currently exposes only the per-section editors.
- Adjust intervals on a slider with a live readout (the SPA forces
  manual numeric typing).
- Add a scheduled query or an osquery flag without hand-editing the
  raw JSON in the Monaco editor.

This PR closes the parity gap. It is intentionally scoped to *parity
with intent*, not new functionality.

## Goals

1. SPA Enrollment page can view + copy + download + upload the env
   certificate, and can view + copy + per-OS download the flags blob.
2. SPA Configuration page shows an authoritative assembled
   `osquery.conf` (server-rendered, not client-stitched).
3. SPA Configuration page exposes inline "Add scheduled query" and
   "Add option flag" forms that mutate the existing Monaco buffer
   without changing the save flow.
4. SPA `IntervalsCard` uses range sliders with live readouts, matching
   the legacy slider UX.
5. `osctrl-api` exposes the two endpoints the SPA needs (cert upload,
   assembled configuration) and extends the existing enroll-target
   switch for per-OS flags.

## Non-goals

- New auth or permission models. Everything new is AdminLevel-gated.
- A JSON-validity pass/fail badge on each editor (Monaco's inline
  squigglies cover this).
- Modal wizards. The add-query and add-flag forms live inline at the
  bottom of their respective editor cards.
- SPA unit tests for the new sections. The existing EnrollPage and
  EnvConfigPage have minimal component coverage; the new sections
  match that pattern. Backend gets full table-driven tests.
- A "preview before save" diff for the add-query/add-flag forms.
  The user reviews the resulting JSON in the Monaco editor before
  clicking Save — same as legacy.

## Backend changes (osctrl-api)

### Per-OS flags — extend `EnvEnrollHandler`

`cmd/api/handlers/environments.go` already handles
`GET /api/v1/environments/{env}/enroll/{target}` for
`secret`, `cert`, `flags`, `enroll.sh`, `enroll.ps1`. Add four cases:

| target | secret path | cert path |
|---|---|---|
| `flagsLinux` | `/etc/osquery/osctrl-{env}.secret` | `/etc/osquery/osctrl-{env}.crt` |
| `flagsMac` | `/private/var/osquery/osctrl-{env}.secret` | `/private/var/osquery/osctrl-{env}.crt` |
| `flagsWindows` | `C:\Program Files\osquery\osctrl-{env}.secret` | `C:\Program Files\osquery\osctrl-{env}.crt` |
| `flagsFreeBSD` | `/usr/local/etc/osctrl-{env}.secret` | `/usr/local/etc/osctrl-{env}.crt` |

Each case calls
`environments.GenerateFlags(env, secretPath, certPath, h.OsqueryValues)`
(already exists in `pkg/environments/flags.go`) and returns the result
in the existing `types.ApiDataResponse{Data: ...}` envelope.

Paths are constants in legacy at `cmd/admin/handlers/templates.go`
lines 968–984. Lift them to `cmd/api/handlers/environments.go` as a
private `osFlagPaths` map so the cases stay compact. Do not extract to
`pkg/environments` — the paths are an installer convention, not a
shared business rule.

No new route mount; the existing `GET .../enroll/{target}` accepts
the new targets through the switch.

### Cert upload — new `EnvCertUploadHandler`

`POST /api/v1/environments/{env}/enroll/cert`

Request body:
```json
{ "certificate_b64": "<base64-encoded PEM>" }
```

Validation (option **b** from brainstorm — parse-check):

1. base64-decode `certificate_b64`. Fail → 400 `"invalid base64"`.
2. `pem.Decode` the bytes. Require at least one block of type
   `CERTIFICATE`. Fail → 400 `"no CERTIFICATE PEM block found"`.
3. `x509.ParseCertificate` the block's `Bytes`. Fail → 400
   `"invalid x509 certificate"`.
4. Do NOT check expiry, CA chain, or hostname. Lab certs (self-signed,
   not-yet-valid, expired) are common in dev and should not be
   refused at this layer.

On success: call `h.Envs.UpdateCertificate(env.UUID, pemString)`. The
stored value is the *original PEM string* (the result of
`pem.EncodeToMemory` of the parsed block — canonicalized, no
surrounding whitespace), not the user's literal base64 input.

Auth: AdminLevel on the env. Audit log: `h.AuditLog.NewEnvAction(...)`
with action `"upload_cert"`.

Response on success: 200 `{"message":"certificate updated"}`.

### Assembled configuration — new `EnvConfigurationHandler`

`GET /api/v1/environments/{env}/configuration`

Behavior:

1. AdminLevel check on the env.
2. Call `h.Envs.RefreshConfiguration(env.UUID)` to ensure the stored
   `env.Configuration` reflects the current parts. (This is cheap —
   it stitches options/schedule/packs/decorators/atc into one indented
   JSON and writes back to the row.) On error, return 500
   `"error assembling configuration"`.
3. Re-fetch the env, return
   `{"data": env.Configuration}` (same envelope as the enroll targets,
   so the SPA client can reuse the `DataResponse` type).

Auth: AdminLevel on the env. Audit log: not required — this is a read.

### Routes (`cmd/api/main.go`)

Two new lines (per-OS flags ride the existing enroll/{target} GET):

```go
muxAPI.Handle(
  "POST "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/cert",
  handlerAuthCheck(http.HandlerFunc(handlersApi.EnvCertUploadHandler), ...))
muxAPI.Handle(
  "GET "+_apiPath(apiEnvironmentsPath)+"/{env}/configuration",
  handlerAuthCheck(http.HandlerFunc(handlersApi.EnvConfigurationHandler), ...))
```

### Tests (`cmd/api/handlers/environments_test.go`)

Add to the existing table-driven test file:

**Per-OS flags** — 4 subtests, one per OS. Each:
- Hits the existing enroll handler with the new target.
- Asserts 200 and that the returned `Data` string contains the
  platform's expected secret path substring
  (`/etc/osquery` for Linux, etc.).

**Cert upload** — 5 subtests:
| Case | Body | Expected |
|---|---|---|
| valid PEM | base64 of a real test PEM | 200, env.Certificate updated |
| junk base64 | `"!!!"` | 400 |
| valid base64, not PEM | base64 of `"hello"` | 400 |
| valid PEM but wrong type | base64 of a `PRIVATE KEY` block | 400 |
| no auth | omit token | 401 |

Use `x509.CreateCertificate` with a self-signed template at test setup
to avoid embedding a hardcoded PEM.

**Configuration** — 1 subtest:
- Pre-seed the env with non-empty options/schedule/packs.
- Hit `GET .../configuration`.
- Assert 200 and that the returned `Data` string is valid JSON
  containing all section keys.

## SPA changes (frontend/)

### `features/enrollment/EnrollPage.tsx`

Two new cards added to the main column under existing sections.
Both follow the visual pattern of the existing
`EnrollSecretCard` (heading row + body + action row).

**CertificateCard**:
- Heading: "Server certificate"
- Body: Monaco editor (`language="plaintext"`, `readOnly=true`,
  height ≈ 180px) showing `env.certificate` (empty-state copy if
  none configured).
- Actions: `Copy`, `Download` (.crt file named
  `osctrl-{env}.crt`), `Upload` (file input → `FileReader.readAsArrayBuffer`
  → `btoa` → `uploadEnrollCert(env, b64)` → invalidate
  `['env', env]` query).
- Upload errors surface via the existing `Feedback` component below
  the actions.

**FlagsCard**:
- Heading: "Osquery flags"
- Body: Monaco editor (plaintext, readOnly, ≈220px) showing
  `env.flags`.
- Actions: `Copy`, then four buttons — `Linux`, `macOS`, `Windows`,
  `FreeBSD` — each calling `getEnrollFlagsOS(env, ...)` and
  triggering a browser download named `osctrl-{env}.flags`.

### `features/environments/EnvConfigPage.tsx`

**Assembled configuration section** (new, between IntervalsCard and
the per-section editors):
- TanStack Query: `['env-configuration', env]`, fetched via
  `getEnvironmentConfiguration(env)`.
- Read-only Monaco (`language="json"`, height ≈ 360px).
- Invalidate this query in the `onSuccess` of every save mutation
  on the page so the assembled doc refreshes after edits.

**IntervalsCard slider migration**:
- Replace `<input type="number">` with
  `<input type="range" min={10} max={86400} step={1}>`.
- Live value rendered alongside as `<output>{value} seconds</output>`.
- Three sliders: Configuration, Logging, Query — matching legacy
  `conf_range`, `logging_range`, `query_range`.
- Slider styled with the SPA's token system (signal-teal track on
  the filled portion). Keyboard a11y: arrow keys = ±1s, PgUp/PgDn = ±60s,
  Home/End = clamp to min/max.
- Save button stays. Same mutation, same audit log.
- Reason for `step={1}`: matches legacy, lets operators land on
  exact prime-friendly values like 311 if they want.

**Per-section documentation links** (parity with legacy
`title="Documentation"` icon in each section header):

Add a small `Docs ↗` link in the heading row of each config section,
opening the upstream osquery docs in a new tab. Reuses the exact URLs
the legacy uses so they stay in sync as upstream evolves:

| Section | URL |
|---|---|
| Options | https://osquery.readthedocs.io/en/stable/deployment/configuration/#options |
| Schedule | https://osquery.readthedocs.io/en/stable/deployment/configuration/#schedule |
| Packs | https://osquery.readthedocs.io/en/stable/deployment/configuration/#packs |
| ATC | https://osquery.readthedocs.io/en/stable/deployment/configuration/#automatic-table-construction |
| Decorators | https://osquery.readthedocs.io/en/stable/deployment/configuration/#decorator-queries |
| Configuration (assembled) | https://osquery.readthedocs.io/en/stable/deployment/configuration/ |
| Flags (osquery CLI) | https://osquery.readthedocs.io/en/stable/installation/cli-flags/ |

Implementation: single small `<DocsLink href={...} />` component in
`features/environments/EnvConfigPage.tsx` (and shared with EnrollPage
for the Flags card via export). Uses `target="_blank"
rel="noopener noreferrer"` and a `lucide-react` `ExternalLink` icon
at 12px. Placed inline next to the section title.

**Add-scheduled-query inline form** at the bottom of the Schedule
section:
- Fields: `name` (text), `query` (multiline textarea), `interval`
  (number, default 3600), `platform` (select: all/linux/darwin/windows/freebsd),
  optional `version` (text), optional `description` (text), `snapshot`
  (checkbox).
- "Add to schedule" button:
  1. `JSON.parse` the current Monaco draft for schedule.
  2. If parse fails, surface "schedule JSON must be valid first".
  3. Construct entry:
     ```js
     { query, interval, platform?, version?, description?, snapshot? }
     ```
     Omit empty optional fields.
  4. Assign `parsed[name] = entry`. Duplicate names overwrite
     (parity with legacy — object semantics).
  5. `JSON.stringify(parsed, null, 2)` and update the draft.
  6. Clear the form.
- User reviews in Monaco, then clicks the existing Save for that
  section. No auto-save.

**Add-option-flag inline form** at the bottom of the Options section:
- Fields: `flag_name` (text), `value` (text).
- "Add to options" button:
  1. `JSON.parse` the current Monaco draft for options.
  2. Parse-failure handling same as above.
  3. `parsed[flag_name.trim()] = value`. Overwrite on dup.
  4. Re-serialize and update draft.
  5. Clear the form.
- Flag name regex: `^[a-zA-Z0-9_]+$` (osquery flag convention).
  Validation runs on blur with inline error.

### `api/enrollment.ts` additions

```ts
export type FlagsOSTarget = 'flagsLinux' | 'flagsMac' | 'flagsWindows' | 'flagsFreeBSD';
export function getEnrollFlagsOS(env: string, target: FlagsOSTarget): Promise<DataResponse>;
export function uploadEnrollCert(env: string, certificateB64: string): Promise<MessageResponse>;
```

### `api/environments.ts` additions

```ts
export function getEnvironmentConfiguration(env: string): Promise<{ data: string }>;
```

## Permissions and audit

Cert upload: AdminLevel on the env. Audit log entry. Other reads
(`/configuration`, per-OS flags): AdminLevel on the env (same as
existing enroll-target reads). No audit on reads — matches existing
pattern.

## Error handling

Backend: every new handler uses `apiErrorResponse` with the same
shape as siblings — `{"error": "...", "code": "..."}` for failures.
HTTP codes: 400 for bad input, 401 for unauthenticated, 403 for
insufficient perms, 404 for missing env, 500 for DB / file errors.

Frontend: every new mutation uses the existing `Feedback` component
to render success and error messages. Failed downloads (network /
401) surface via the existing toast system.

## Verification

Local Proxmox deployment (192.168.99.118):

1. `git checkout pr/enroll-config-parity`, push to ubuntu@VM, rebuild
   admin + api + frontend containers.
2. Curl smoke: cert upload (valid + each rejection case), per-OS flag
   download (each OS), configuration GET.
3. Browser: navigate to `/_app/env/dev/enroll`, exercise cert
   download/upload, per-OS flag downloads.
4. Browser: navigate to `/_app/env/dev/config`, exercise sliders +
   live readouts, add a scheduled query + save + verify it lands in
   Monaco, add an option flag + save + verify, view assembled
   configuration after each save and confirm it refreshes.

## Files modified

**Backend:**
- `cmd/api/handlers/environments.go` — extend EnvEnrollHandler,
  add EnvCertUploadHandler, add EnvConfigurationHandler, add
  osFlagPaths constant map.
- `cmd/api/main.go` — register 2 new routes.
- `cmd/api/handlers/environments_test.go` — 10 new subtests.

**Frontend:**
- `frontend/src/features/enrollment/EnrollPage.tsx` — add
  CertificateCard, FlagsCard, DocsLink usage on the Flags card.
- `frontend/src/features/environments/EnvConfigPage.tsx` — add
  AssembledConfigSection, swap IntervalsCard inputs to sliders, add
  AddQueryForm + AddFlagForm, DocsLink on every section heading.
- `frontend/src/components/atoms/DocsLink.tsx` — new shared atom.
- `frontend/src/api/enrollment.ts` — add 2 functions.
- `frontend/src/api/environments.ts` — add 1 function.

## Risks

- **`UpdateCertificate` may have side effects** beyond the DB write
  (e.g., bumping a cert version that osquery agents pin against).
  Need to read its implementation before merging to confirm it's
  safe for online cert rotation. If it isn't, the upload endpoint
  must include an explicit warning in the response and/or the SPA
  must gate it behind a confirm dialog.
- **`RefreshConfiguration` cost**: assembles + serializes every
  call. If the configuration tab gets polled aggressively this is a
  per-tab N×assembly cost. Mitigation: SPA only fetches on mount and
  on save-success, not on a timer. Document this in code comment.
- **Per-OS flag paths drift** — legacy may evolve installer
  conventions. The four constants are duplicated between
  `cmd/admin/handlers/templates.go` and the new map. Document the
  duplication in a code comment so future changes update both. (No
  refactor in this PR — single-responsibility scope.)
