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

export interface SantaConfig {
  client_mode: SantaClientMode;
  batch_size: number;
  enable_transitive_rules: boolean;
  removable_media: SantaMediaAction;
  removable_media_flags: string[] | null;
  /** Empty means encrypted volumes follow removable_media. */
  encrypted_removable_media: SantaMediaAction | '';
  encrypted_removable_media_flags: string[] | null;
  /** Base https URL of this UI; empty turns approval requests off. */
  approval_url: string;
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
}

export interface SantaModeOverride extends SantaModeOverrideInput {
  id: number;
  created_by: string;
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
}

export interface SantaEventsPage {
  events: SantaEvent[];
  total: number;
  page: number;
}

export const santaQueryKey = (env: string, part: 'config' | 'rules' | 'modes' | 'machines' | 'events', ...rest: unknown[]) =>
  ['santa', env, part, ...rest] as const;

function envPath(env: string): string {
  return `/api/v1/santa/${encodeURIComponent(env)}`;
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

/** GET /api/v1/santa/{env}/config */
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

/** DELETE /api/v1/santa/{env}/modes/{id} */
export function deleteSantaModeOverride(env: string, id: number): Promise<unknown> {
  return apiFetch<unknown>(`${envPath(env)}/modes/${id}`, { method: 'DELETE' });
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
}

/**
 * POST /api/v1/santa/{env}/requests — any signed-in account. Returns the
 * existing pending request when the file was already requested for the machine.
 */
export function createSantaRequest(env: string, body: { sha256: string; machine_id: string; justification: string }): Promise<SantaOwnRequest> {
  return apiFetch<SantaOwnRequest>(`${envPath(env)}/requests`, jsonInit('POST', body));
}

/** GET /api/v1/santa/{env}/requests/mine — the caller's own requests. */
export function listMySantaRequests(env: string): Promise<SantaOwnRequest[]> {
  return apiFetch<SantaOwnRequest[]>(`${envPath(env)}/requests/mine`);
}

/** GET /api/v1/santa/{env}/events */
export function listSantaEvents(env: string, page = 1, pageSize = SANTA_EVENTS_PAGE_SIZE): Promise<SantaEventsPage> {
  return apiFetch<SantaEventsPage>(`${envPath(env)}/events?page=${page}&page_size=${pageSize}`);
}
