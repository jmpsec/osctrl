/**
 * Santa sync-server API client. Routes need the environment admin
 * permission. They are not registered (404) when the feature flag is off, and
 * answer 503 only if the manager is missing while enabled; the SPA only calls
 * them when features.santa is true.
 */
import { apiFetch } from './client';

export type SantaClientMode = 'MONITOR' | 'LOCKDOWN';
export type SantaRuleType = 'BINARY' | 'CERTIFICATE' | 'TEAMID' | 'SIGNINGID' | 'CDHASH';
export type SantaPolicy = 'ALLOWLIST' | 'ALLOWLIST_COMPILER' | 'BLOCKLIST' | 'SILENT_BLOCKLIST' | 'CEL';
export type SantaScope = 'env' | 'tag' | 'node';

export const SANTA_RULE_TYPES: SantaRuleType[] = ['BINARY', 'CERTIFICATE', 'TEAMID', 'SIGNINGID', 'CDHASH'];
export const SANTA_POLICIES: SantaPolicy[] = ['ALLOWLIST', 'ALLOWLIST_COMPILER', 'BLOCKLIST', 'SILENT_BLOCKLIST', 'CEL'];
export const SANTA_SCOPES: SantaScope[] = ['env', 'tag', 'node'];
export const SANTA_EVENTS_PAGE_SIZE = 50;
/** Header the Santa client sends via SyncExtraHeaders. */
export const SANTA_TOKEN_HEADER = 'X-Osctrl-Santa-Token';

export type SantaMediaAction = 'ALLOW' | 'BLOCK' | 'REMOUNT';
export const SANTA_MEDIA_ACTIONS: SantaMediaAction[] = ['ALLOW', 'BLOCK', 'REMOUNT'];
/** Mount options offered in the UI; the API also accepts async and -j. */
export const SANTA_REMOUNT_FLAGS = ['rdonly', 'noexec', 'nosuid', 'nodev', 'nobrowse', 'noowners'];

export type SantaFileAccessAction = '' | 'NONE' | 'AUDIT_ONLY' | 'DISABLE';
export const SANTA_FILE_ACCESS_ACTIONS: SantaFileAccessAction[] = ['', 'NONE', 'AUDIT_ONLY', 'DISABLE'];

export interface SantaGroupTag {
  group: string;
  tag: string;
}

export interface SantaConfig {
  client_mode: SantaClientMode;
  batch_size: number;
  full_sync_interval_seconds?: number;
  enable_transitive_rules: boolean;
  removable_media: SantaMediaAction;
  removable_media_flags: string[] | null;
  /** Empty means encrypted volumes follow removable_media. */
  encrypted_removable_media: SantaMediaAction | '';
  encrypted_removable_media_flags: string[] | null;
  /** Base https URL of this UI; empty turns approval requests off. */
  approval_url: string;
  /** Alert channel IDs told about each new request; changing it requires superuser. */
  notify_channels: number[] | null;
  /** Email alert channel that tells requesters about decisions and MONITOR ends; 0 is off. */
  requester_channel?: number;
  /** Votes that allow a blocked file on each voter's machine; 0 is off. */
  vote_local_threshold: number;
  /** Votes that allow the file in the whole environment; 0 is off. */
  vote_global_threshold: number;
  /** Votes older than this many days are deleted; 0 keeps them. */
  vote_expiry_days?: number;
  /** Longest temporary MONITOR mode in hours, at most 24; 0 is 24. */
  max_monitor_hours?: number;
  /** Overrides the action of MDM-deployed file access rules; empty leaves clients unchanged. */
  override_file_access_action: SantaFileAccessAction;
  /** Clients hash the bundle of a blocked binary and upload its other binaries. */
  enable_bundles: boolean;
  enable_all_event_upload: boolean;
  disable_unknown_event_upload: boolean;
  /** Paths allowed or blocked when no rule matches; empty is off. */
  allowed_path_regex: string;
  blocked_path_regex: string;
  /** Block dialog button URL, with Santa placeholders; overrides the approval link. */
  event_detail_url: string;
  event_detail_text: string;
  group_tags?: SantaGroupTag[];
  /** How the primary user matches an osctrl user: '' exact, 'local_part' or 'email'. */
  group_match?: string;
  /** Changes that weaken enforcement wait for a second environment admin. */
  require_second_admin?: boolean;
  /** osctrl users and IdP groups who decide approval requests without being environment admins. */
  approver_users?: string[];
  approver_groups?: string[];
  /** The token itself is never returned, only whether one exists. */
  token_set: boolean;
}

export type SantaConfigUpdate = Omit<SantaConfig, 'token_set'>;

export interface SantaRuleInput {
  identifier: string;
  rule_type: SantaRuleType;
  policy: SantaPolicy;
  cel_expr: string;
  custom_msg: string;
  custom_url: string;
  scope: SantaScope;
  scope_value: string;
}

export interface SantaRule extends SantaRuleInput {
  id: number;
  created_at: string;
  created_by: string;
}

export interface SantaImportIssue {
  /** Position of the rule in the imported list, starting at 0. */
  index: number;
  rule: Partial<SantaRuleInput>;
  reason: string;
}

export interface SantaImportResult {
  new: number;
  duplicate: number;
  conflicts: SantaImportIssue[];
  invalid: SantaImportIssue[];
  applied: boolean;
}

export interface SantaMachine {
  machine_id: string;
  serial_number: string;
  hostname: string;
  os_version: string;
  santa_version: string;
  primary_user: string;
  /** Mode the client reported at its last preflight. */
  client_mode: string;
  /** Mode osctrl sent at the last preflight; empty for machines that synced before overrides existed. */
  assigned_mode: string;
  mode_source: 'env' | 'tag' | 'node' | '';
  rule_count: number;
  last_sync_at: string | null;
}

export interface SantaModeOverrideInput {
  scope: 'tag' | 'node';
  scope_value: string;
  client_mode: SantaClientMode;
  /** Temporary MONITOR mode for 1 to max_monitor_hours (node scope only); omitted or 0 is permanent. */
  hours?: number;
}

/** Hours offered for temporary MONITOR mode; the API accepts 1 to the environment's max_monitor_hours (24 by default). */
export const SANTA_MONITOR_HOURS = [1, 2, 4, 8, 24];

export interface SantaModeOverride extends SantaModeOverrideInput {
  id: number;
  created_by: string;
  /** Set for temporary MONITOR mode; null is permanent. */
  expires_at: string | null;
}

export interface SantaEvent {
  id: number;
  file_sha256: string;
  file_path: string;
  file_name: string;
  executing_user: string;
  decision: string;
  team_id: string;
  signing_id: string;
  cd_hash: string;
  bundle_id: string;
  machine_id: string;
  executed_at: string;
  /** Carve started from this event to retrieve the file; empty when none. */
  carve_name: string;
}

/**
 * POST /api/v1/santa/{env}/events/{id}/carve — carve the event's file on its
 * machine through the carves endpoint (carve access and sensitive paths apply).
 */
export function carveSantaEvent(env: string, id: number): Promise<{ query_name: string }> {
  return apiFetch<{ query_name: string }>(`${envPath(env)}/events/${id}/carve`, { method: 'POST' });
}

export interface SantaCert {
  sha256: string;
  cn: string;
  org: string;
  ou: string;
  valid_from: string;
  valid_until: string;
}

/**
 * What the stored events say about one file hash. Every identity field is
 * reported by Santa clients; dates and counts cover the kept events only.
 */
export interface SantaBinary {
  sha256: string;
  file_name: string;
  file_path: string;
  team_id: string;
  signing_id: string;
  cd_hash: string;
  bundle_id: string;
  bundle_name: string;
  bundle_version: string;
  bundle_path: string;
  /** Leaf first; null or empty when unsigned or not reported. */
  signing_chain: SantaCert[] | null;
  first_seen: string;
  last_seen: string;
  events: number;
  blocked: number;
  machines: number;
  /** The machines that reported it most recently, at most 100; kept after events are pruned. */
  machine_list: SantaBinaryMachine[] | null;
  rules: SantaRule[] | null;
  /** Cached verdict; absent when no risk check is configured. */
  risk?: SantaRisk;
  /** Newest event of the file, to retrieve it from the machine that last ran it. */
  latest_event_id: number;
  latest_machine_id: string;
  latest_carve: string;
}

export interface SantaBinaryMachine {
  machine_id: string;
  /** Empty for a machine no longer known. */
  hostname: string;
  file_name: string;
  first_seen: string;
  last_seen: string;
  events: number;
}

/** GET /api/v1/santa/{env}/binaries/{sha256} — 404 when osctrl never received an event of the hash. */
export function getSantaBinary(env: string, sha256: string): Promise<SantaBinary> {
  return apiFetch<SantaBinary>(`${envPath(env)}/binaries/${encodeURIComponent(sha256)}`);
}

export interface SantaLockdownCandidate {
  machine_id: string;
  hostname: string;
  mode_source: string;
  last_sync_at: string | null;
  /** ALLOW_UNKNOWN executions in the window: what LOCKDOWN would have blocked. */
  would_block: number;
  /** None would have blocked, and the machine synced in the window. */
  ready: boolean;
}

export interface SantaRankedBinary {
  sha256: string;
  file_name: string;
  team_id: string;
  signing_id?: string;
  cd_hash?: string;
  events: number;
  machines: number;
}

/** One UTC day of the report window. */
export interface SantaTrendDay {
  day: string;
  blocked: number;
  /** ALLOW_UNKNOWN executions, and the machines that had any. */
  would_block: number;
  would_block_machines: number;
}

export interface SantaRankedTeam {
  team_id: string;
  events: number;
  machines: number;
  binaries: number;
}

/** Computed from the events received in the last `days` days; ranked lists hold at most 20. */
export interface SantaReport {
  days: number;
  since: string;
  lockdown_ready: SantaLockdownCandidate[] | null;
  top_blocked: SantaRankedBinary[] | null;
  top_blocked_teams: SantaRankedTeam[] | null;
  coverage_gaps: SantaRankedBinary[] | null;
  /** Oldest day first. */
  trend?: SantaTrendDay[] | null;
}

export const SANTA_REPORT_DAYS = [7, 14, 30];

/** GET /api/v1/santa/{env}/reports?days= — 1 to 30 days. */
export function getSantaReport(env: string, days: number): Promise<SantaReport> {
  return apiFetch<SantaReport>(`${envPath(env)}/reports?days=${days}`);
}

/** The report as CSV, for an <a href download>: the browser sends the session cookie. */
export function getSantaReportCSVUrl(env: string, days: number): string {
  return `${envPath(env)}/reports?days=${days}&format=csv`;
}

export interface SantaEventsPage {
  events: SantaEvent[];
  total: number;
  page: number;
}

export const santaQueryKey = (env: string, part: 'config' | 'rules' | 'modes' | 'machines' | 'events' | 'requests' | 'binaries' | 'reports' | 'file-access' | 'access' | 'voters', ...rest: unknown[]) =>
  ['santa', env, part, ...rest] as const;

function envPath(env: string): string {
  return `/api/v1/santa/${encodeURIComponent(env)}`;
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

/** GET /api/v1/santa/{env}/config */
export interface SantaAccess {
  /** Environment admin: the whole Santa page. */
  admin: boolean;
  /** Approver: the Requests tab only. */
  approver: boolean;
}

/** GET /api/v1/santa/{env}/access — any signed-in account. */
export function getSantaAccess(env: string): Promise<SantaAccess> {
  return apiFetch<SantaAccess>(`${envPath(env)}/access`);
}

export function getSantaConfig(env: string): Promise<SantaConfig> {
  return apiFetch<SantaConfig>(`${envPath(env)}/config`);
}

/** PUT /api/v1/santa/{env}/config */
export function putSantaConfig(env: string, body: SantaConfigUpdate): Promise<SantaConfig> {
  return apiFetch<SantaConfig>(`${envPath(env)}/config`, jsonInit('PUT', body));
}

/** POST /api/v1/santa/{env}/token — the plaintext token is returned once. */
export function rotateSantaToken(env: string): Promise<{ token: string }> {
  return apiFetch<{ token: string }>(`${envPath(env)}/token`, { method: 'POST' });
}

/** GET /api/v1/santa/{env}/rules */
export function listSantaRules(env: string): Promise<SantaRule[]> {
  return apiFetch<SantaRule[]>(`${envPath(env)}/rules`);
}

/** POST /api/v1/santa/{env}/rules — 409 when the rule already exists, 400 on invalid input. */
export function createSantaRule(env: string, body: SantaRuleInput): Promise<SantaRule> {
  return apiFetch<SantaRule>(`${envPath(env)}/rules`, jsonInit('POST', body));
}

/** PUT /api/v1/santa/{env}/rules/{id} — 409 when the edit duplicates another rule, 400 on invalid input. */
export function updateSantaRule(env: string, id: number, body: SantaRuleInput): Promise<SantaRule> {
  return apiFetch<SantaRule>(`${envPath(env)}/rules/${id}`, jsonInit('PUT', body));
}

/**
 * POST /api/v1/santa/{env}/rules/import — nothing is stored on a dry run, or when
 * any rule is conflicting or invalid (applied is false). Existing rules are never changed.
 */
export function importSantaRules(env: string, rules: unknown[], dryRun: boolean): Promise<SantaImportResult> {
  return apiFetch<SantaImportResult>(`${envPath(env)}/rules/import${dryRun ? '?dry_run=true' : ''}`, jsonInit('POST', rules));
}

/** DELETE /api/v1/santa/{env}/rules/{id} */
export function deleteSantaRule(env: string, id: number): Promise<unknown> {
  return apiFetch<unknown>(`${envPath(env)}/rules/${id}`, { method: 'DELETE' });
}

/** GET /api/v1/santa/{env}/modes */
export function listSantaModeOverrides(env: string): Promise<SantaModeOverride[]> {
  return apiFetch<SantaModeOverride[]>(`${envPath(env)}/modes`);
}

/** PUT /api/v1/santa/{env}/modes — creates the override or replaces the mode for the same tag or node. */
export function setSantaModeOverride(env: string, body: SantaModeOverrideInput): Promise<SantaModeOverride> {
  return apiFetch<SantaModeOverride>(`${envPath(env)}/modes`, jsonInit('PUT', body));
}

/** DELETE /api/v1/santa/{env}/modes/{id} — on a temporary MONITOR override, ends it now. */
export function deleteSantaModeOverride(env: string, id: number): Promise<unknown> {
  return apiFetch<unknown>(`${envPath(env)}/modes/${id}`, { method: 'DELETE' });
}

/** POST /api/v1/santa/{env}/modes/{id}/extend — adds hours to a temporary MONITOR override. */
export function extendSantaMonitor(env: string, id: number, hours: number): Promise<SantaModeOverride> {
  return apiFetch<SantaModeOverride>(`${envPath(env)}/modes/${id}/extend`, jsonInit('POST', { hours }));
}

/** GET /api/v1/santa/{env}/machines */
export function listSantaMachines(env: string): Promise<SantaMachine[]> {
  return apiFetch<SantaMachine[]>(`${envPath(env)}/machines`);
}

export type SantaRequestStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** The requester's view of an approval request. */
export interface SantaOwnRequest {
  id: number;
  file_sha256: string;
  machine_id: string;
  status: SantaRequestStatus;
  created_at: string;
  /** Empty when someone else made the request. */
  justification: string;
  /** The approver's reason, when one was given. */
  reason: string;
  /** monitor: temporary MONITOR mode for monitor_hours, no file fields. */
  kind: '' | 'monitor';
  monitor_hours: number;
}

/** The approver's view of an approval request. File fields are reported by the Santa client. */
export interface SantaRequest extends SantaOwnRequest {
  file_name: string;
  file_path: string;
  signing_id: string;
  team_id: string;
  executing_user: string;
  requester: string;
  decided_by: string;
  decided_at: string | null;
  /** The allow rule an approval created or reused; 0 otherwise. */
  rule_id: number;
  /** The approver allowed the file although a risk check flagged it. */
  risk_override: boolean;
  /** Type of the allow rule an approval created; empty for MONITOR and older approvals. */
  rule_type?: SantaRuleType | '';
  /** Leaf certificate of the blocked file, from its event. */
  cert_sha256?: string;
  /** Binaries the client uploaded for the file's bundle. */
  bundle_binaries?: number;
  /** Cached verdict; absent when no risk check is configured. */
  risk?: SantaRisk;
}

export type SantaRiskVerdict = 'clean' | 'flagged' | 'unknown' | 'error' | 'unchecked';

export interface SantaRisk {
  /** flagged if any check flagged, error if any failed, clean if any found it clean. */
  verdict: SantaRiskVerdict;
  checks: { check: string; verdict: SantaRiskVerdict; detail: string; checked_at: string; expires_at: string }[] | null;
}

/** POST /api/v1/santa/{env}/binaries/{sha256}/risk — runs the checks that have no fresh verdict. */
export function checkSantaRisk(env: string, sha256: string): Promise<SantaRisk> {
  return apiFetch<SantaRisk>(`${envPath(env)}/binaries/${encodeURIComponent(sha256)}/risk`, { method: 'POST' });
}

export interface SantaDecision {
  decision: 'approve' | 'deny';
  /** On approve: node is the requesting machine. */
  scope?: SantaScope;
  /** Tag name, with scope tag. */
  scope_value?: string;
  /** Environment admins: the allow rule's type, with the identifier from the request; BINARY by default. */
  rule_type?: SantaRuleType;
  /** Environment admins: also allow every uploaded binary of the file's bundle. */
  bundle?: boolean;
  /** Required to deny; the requester sees it. */
  reason: string;
  /** Approve although a risk check flagged the file; needs a reason. */
  override?: boolean;
}

/**
 * POST /api/v1/santa/{env}/requests — any signed-in account. Returns the
 * existing pending request when the file was already requested for the machine.
 */
export function createSantaRequest(
  env: string,
  body: { sha256: string; machine_id: string; justification: string } | { kind: 'monitor'; machine_id: string; hours: number; justification: string },
): Promise<SantaOwnRequest> {
  return apiFetch<SantaOwnRequest>(`${envPath(env)}/requests`, jsonInit('POST', body));
}

/** GET /api/v1/santa/{env}/requests/mine — the caller's own requests. */
export function listMySantaRequests(env: string): Promise<SantaOwnRequest[]> {
  return apiFetch<SantaOwnRequest[]>(`${envPath(env)}/requests/mine`);
}

export interface SantaVoteStatus {
  votes: number;
  /** 0 is off. */
  local_threshold: number;
  /** 0 is off. */
  global_threshold: number;
  voted: boolean;
  /** What the votes reached for the caller: node is their own machine. */
  allowed: '' | 'node' | 'env';
}

/** GET /api/v1/santa/{env}/votes — any signed-in account. */
export function getSantaVotes(env: string, sha256: string): Promise<SantaVoteStatus> {
  return apiFetch<SantaVoteStatus>(`${envPath(env)}/votes?sha256=${encodeURIComponent(sha256)}`);
}

/** POST /api/v1/santa/{env}/votes — one vote per account and file. 409 when a rule blocks the file. */
export function voteSantaFile(env: string, body: { sha256: string; machine_id: string }): Promise<SantaVoteStatus> {
  return apiFetch<SantaVoteStatus>(`${envPath(env)}/votes`, jsonInit('POST', body));
}

/** DELETE /api/v1/santa/{env}/votes — withdraws the caller's own vote; rules already made stay. */
export function withdrawSantaVote(env: string, sha256: string): Promise<SantaVoteStatus> {
  return apiFetch<SantaVoteStatus>(`${envPath(env)}/votes?sha256=${encodeURIComponent(sha256)}`, { method: 'DELETE' });
}

export interface SantaVote {
  id: number;
  created_at: string;
  voter: string;
  machine_id: string;
}

/** GET /api/v1/santa/{env}/votes/{sha256} — environment admins: who voted, oldest first. */
export function listSantaVoters(env: string, sha256: string): Promise<SantaVote[]> {
  return apiFetch<SantaVote[]>(`${envPath(env)}/votes/${encodeURIComponent(sha256)}`);
}

/** GET /api/v1/santa/{env}/requests — newest first, at most 500; an empty status lists every status. */
export function listSantaRequests(env: string, status: SantaRequestStatus | '' = ''): Promise<SantaRequest[]> {
  return apiFetch<SantaRequest[]>(`${envPath(env)}/requests${status ? `?status=${status}` : ''}`);
}

/**
 * POST /api/v1/santa/{env}/requests/{id}/decision — approving creates the allow
 * rule. 409 when the request is no longer pending or a block rule is in the way.
 */
export function decideSantaRequest(env: string, id: number, body: SantaDecision): Promise<SantaRequest> {
  return apiFetch<SantaRequest>(`${envPath(env)}/requests/${id}/decision`, jsonInit('POST', body));
}

/** GET /api/v1/santa/{env}/requests/{id} */
export function getSantaRequest(env: string, id: number): Promise<SantaRequest> {
  return apiFetch<SantaRequest>(`${envPath(env)}/requests/${id}`);
}

/**
 * POST /api/v1/santa/{env}/requests/link — decides through a notification
 * link. 410 when the link was used, has expired or is for the other action.
 */
export function decideSantaRequestByLink(env: string, token: string, body: SantaDecision): Promise<SantaRequest> {
  return apiFetch<SantaRequest>(`${envPath(env)}/requests/link`, jsonInit('POST', { token, ...body }));
}

/** A violation of a file access rule; every field but the IDs is written by the client. */
export interface SantaFileAccessEvent {
  id: number;
  machine_id: string;
  rule_name: string;
  rule_version: string;
  target: string;
  decision: string;
  accessed_at: string;
  /** The accessing process first, then its parents. */
  process_chain: { pid: number; file_path: string; file_sha256: string; signing_id: string; team_id: string }[] | null;
}

/** GET /api/v1/santa/{env}/file-access-events */
export function listSantaFileAccessEvents(
  env: string,
  page = 1,
  filter: SantaFileAccessFilter = {},
  pageSize = SANTA_EVENTS_PAGE_SIZE,
): Promise<{ events: SantaFileAccessEvent[]; total: number; page: number }> {
  return apiFetch(`${envPath(env)}/file-access-events?${pageQuery(page, pageSize, filter)}`);
}

/** Execution event filters; decision is a name or prefix such as BLOCK. */
export interface SantaEventFilter {
  machine_id?: string;
  decision?: string;
  sha256?: string;
}

/** File access event filters; target and process are substrings, without case. */
export interface SantaFileAccessFilter {
  machine_id?: string;
  target?: string;
  process?: string;
  decision?: string;
}

function pageQuery(page: number, pageSize: number, filter: object): string {
  const q = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  for (const [k, v] of Object.entries(filter)) if (v) q.set(k, String(v));
  return q.toString();
}

/** GET /api/v1/santa/{env}/events */
export function listSantaEvents(env: string, page = 1, filter: SantaEventFilter = {}, pageSize = SANTA_EVENTS_PAGE_SIZE): Promise<SantaEventsPage> {
  return apiFetch<SantaEventsPage>(`${envPath(env)}/events?${pageQuery(page, pageSize, filter)}`);
}
