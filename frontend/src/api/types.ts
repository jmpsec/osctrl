/**
 * Shared API types for the osctrl React admin.
 * Snake_case fields match the JSON returned by osctrl-api.
 */

/**
 * Enrichment block returned by GET /api/v1/nodes/{env}/node/{uuid} and on
 * each row in GET /api/v1/nodes/{env}. Parsed and sanitized from the
 * `RawEnrollment` JSON blob that osquery sends during enroll — the enroll
 * secret is deliberately excluded. Every field is optional because nodes
 * with empty / malformed raw enrollments simply don't have this object.
 *
 * Mirrors pkg/types.NodeEnrichment on the Go side.
 */
export interface NodeSystemInfo {
  hardware_vendor?: string;
  hardware_model?: string;
  hardware_version?: string;
  hardware_serial?: string;
  cpu_brand?: string;
  cpu_type?: string;
  cpu_subtype?: string;
  cpu_physical_cores?: string;
  cpu_logical_cores?: string;
  physical_memory?: string;
  computer_name?: string;
  local_hostname?: string;
}

export interface NodeBIOSInfo {
  vendor?: string;
  version?: string;
  date?: string;
  revision?: string;
  address?: string;
  size?: string;
  volume_size?: string;
}

export interface NodeOSInfo {
  name?: string;
  version?: string;
  codename?: string;
  major?: string;
  minor?: string;
  patch?: string;
  platform?: string;
  platform_like?: string;
}

export interface NodeOsqueryRuntime {
  version?: string;
  build_platform?: string;
  build_distro?: string;
  extensions?: string;
  start_time?: string;
  config_valid?: string;
}

export interface NodeEnrichment {
  system?: NodeSystemInfo;
  bios?: NodeBIOSInfo;
  os?: NodeOSInfo;
  osquery?: NodeOsqueryRuntime;
}

export interface OsqueryNode {
  id: number;
  created_at: string;
  updated_at: string;
  uuid: string;
  platform: string;
  platform_version: string;
  osquery_version: string;
  hostname: string;
  localname: string;
  ip_address: string;
  username: string;
  osquery_user: string;
  environment: string;
  cpu: string;
  memory: string;
  hardware_serial: string;
  daemon_hash: string;
  config_hash: string;
  bytes_received: number;
  last_seen: string;
  user_id: number;
  environment_id: number;
  extra_data: string;
  /** Optional enrichment parsed server-side from RawEnrollment (no secrets). */
  system_info?: NodeEnrichment;
}

export type NodeStatus = 'all' | 'active' | 'inactive';
export type NodeSort =
  | 'uuid'
  | 'hostname'
  | 'localname'
  | 'ip'
  | 'platform'
  | 'version'
  | 'osquery'
  | 'lastseen'
  | 'firstseen';
export type SortDir = 'asc' | 'desc';

export interface NodesPagedResponse {
  items: OsqueryNode[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export type NodeLogEntry = Record<string, unknown>;

export interface NodeLogsResponse {
  items: NodeLogEntry[];
  type: 'status' | 'result';
  uuid: string;
  env: string;
  since?: string;
  limit: number;
}

// ---------------------------------------------------------------------------
// Queries types
// ---------------------------------------------------------------------------

export interface DistributedQuery {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  creator: string;
  query: string;
  expected: number;
  executions: number;
  errors: number;
  active: boolean;
  hidden: boolean;
  protected: boolean;
  completed: boolean;
  deleted: boolean;
  expired: boolean;
  type: string;
  path: string;
  environment_id: number;
  extra_data: string;
  expiration: string;
  target: string;
}

export interface QueriesPagedResponse {
  items: DistributedQuery[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export type QueryResultRow = Record<string, unknown>;

export interface QueryResultItem {
  id: number;
  created_at: string;
  uuid: string;
  environment: string;
  name: string;
  data: string;
  status: number;
}

export interface QueryResultsResponse {
  items: QueryResultItem[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  since?: string;
}

export type QueryTarget =
  | 'all'
  | 'all-full'
  | 'active'
  | 'completed'
  | 'expired'
  | 'saved'
  | 'hidden-completed'
  | 'deleted'
  | 'hidden';

export type QuerySortColumn =
  | 'name'
  | 'creator'
  | 'created'
  | 'type'
  | 'expected'
  | 'executions'
  | 'errors';

// ---------------------------------------------------------------------------
// Saved queries
// ---------------------------------------------------------------------------

export interface SavedQuery {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  creator: string;
  query: string;
  environment_id: number;
  extra_data?: string;
}

export interface SavedQueriesPagedResponse {
  items: SavedQuery[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export type SavedQuerySortColumn = 'name' | 'creator' | 'created' | 'updated';

// ---------------------------------------------------------------------------
// Carves
// ---------------------------------------------------------------------------

// The list of carve queries reuses the DistributedQuery shape — same backing
// table. Items in CarvesPagedResponse are rows where type === 'carve'.
export interface CarvesPagedResponse {
  items: DistributedQuery[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface CarveFile {
  carve_id: string;
  session_id: string;
  uuid: string;
  path: string;
  status: string;
  carve_size: number;
  block_size: number;
  total_blocks: number;
  completed_blocks: number;
  archived: boolean;
  created_at: string;
  completed_at: string;
}

export interface CarveDetail {
  query: DistributedQuery;
  files: CarveFile[];
}

// Carves share the same set of targets as queries — they are also
// DistributedQuery rows, just with type=carve.
export type CarveTarget = QueryTarget;

// Carves expose the same sortable columns as queries; the package layer
// reuses QuerySortableColumns. Errors/expected/executions are still valid
// because the underlying rows are DistributedQuery records.
export type CarveSortColumn = QuerySortColumn;

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

export interface AdminTag {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  description: string;
  color: string;
  icon: string;
  created_by: string;
  custom_tag: string;
  auto_tag: boolean;
  environment_id: number;
  tag_type: number;
  cohort: boolean;
}

export interface TagsActionRequest {
  name: string;
  description?: string;
  color?: string;
  icon?: string;
  tagtype?: number;
  custom?: string;
}

// ---------------------------------------------------------------------------
// Users + permissions
// ---------------------------------------------------------------------------

export interface AdminUser {
  id: number;
  created_at: string;
  updated_at: string;
  username: string;
  email: string;
  fullname: string;
  token_expire: string;
  admin: boolean;
  service: boolean;
  uuid: string;
  last_ip_address: string;
  last_user_agent: string;
  last_access: string;
  last_token_use: string;
  environment_id: number;
  // Empty / undefined for the password-login path (default).
  // "oidc" for users JIT-provisioned through the federated callback.
  auth_source?: string;
}

export interface EnvAccess {
  user: boolean;
  query: boolean;
  carve: boolean;
  admin: boolean;
}

export interface SetPermissionsRequest {
  env_uuid: string;
  access: EnvAccess;
}

// Response from GET /api/v1/users/{u}/permissions. Maps env UUID
// to the user's current EnvAccess; envs with no rows are omitted
// (treated as no access — the zero-value EnvAccess).
export interface GetPermissionsResponse {
  username: string;
  permissions: Record<string, EnvAccess>;
}

// Body for POST /api/v1/users/{u}/permissions/all — bulk
// permission set across every environment in the system.
export interface SetPermissionsAllRequest {
  access: EnvAccess;
}

// Response from POST /api/v1/users/{u}/permissions/all.
// updated == total on full success. On error, the api returns 5xx
// and the client falls back to the per-env loop.
export interface SetPermissionsAllResponse {
  updated: number;
  total: number;
  access: EnvAccess;
}

export interface TokenResponse {
  token: string;
  expires: string;
}

export interface UserMeResponse {
  username: string;
  email: string;
  fullname: string;
  admin: boolean;
  service: boolean;
  uuid: string;
  token_expire: string;
  last_access: string;
}

// ---------------------------------------------------------------------------
// osquery schema types
// ---------------------------------------------------------------------------

export interface OsqueryTableColumn {
  name: string;
  description: string;
  type: string;
}

export interface OsqueryTable {
  name: string;
  url: string;
  platforms: string[];
  filter: string;
}
