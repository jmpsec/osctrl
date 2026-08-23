/**
 * Development-only API fixtures for visual review.
 *
 * The adapter is enabled by default in `vite` development mode and is never
 * included in test or production behavior. Set VITE_USE_MOCK_DATA=false to
 * bypass it. Removing it later is intentionally small: delete this file and
 * the import/call in client.ts.
 */

import type {
  AdminTag,
  CarveDetail,
  DistributedQuery,
  NodePosture,
  NodesPagedResponse,
  OsqueryNode,
  OsqueryTable,
  PostureScore,
  QueryResultsResponse,
  SavedQuery,
} from './types';
import type { AuditLogsPagedResponse } from './audit';
import type { NodeActivityBucket, NodeTileSeries, StatsResponse } from './stats';

export type MockApiResult =
  | { matched: true; data: unknown }
  | { matched: false };

const enabled =
  import.meta.env.MODE === 'development' &&
  import.meta.env.VITE_USE_MOCK_DATA !== 'false';

export function isMockDataEnabled(): boolean {
  return enabled;
}

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const now = Date.now();

function ago(milliseconds: number) {
  return new Date(now - milliseconds).toISOString();
}

const ALL_PLATFORMS = ['darwin', 'linux', 'windows'];

function mockOsqueryTable(
  name: string,
  description: string,
  columns: Array<[name: string, type: string, description: string]>,
  platforms = ALL_PLATFORMS,
): OsqueryTable {
  return {
    name,
    description,
    url: `https://osquery.io/schema/5.23.1/#${name}`,
    platforms,
    filter: platforms.map((platform) => `filter-${platform}`).join(' '),
    columns: columns.map(([columnName, type, columnDescription]) => ({
      name: columnName,
      type,
      description: columnDescription,
    })),
  };
}

const mockOsqueryTables: OsqueryTable[] = [
  mockOsqueryTable('osquery_info', 'Build, platform, and runtime information for the running osquery process.', [
    ['version', 'text', 'Osquery version'],
    ['pid', 'bigint', 'Process identifier'],
    ['uuid', 'text', 'Unique process instance identifier'],
    ['instance_id', 'text', 'Ephemeral instance identifier'],
    ['config_hash', 'text', 'Hash of the active configuration'],
    ['build_platform', 'text', 'Platform used to build osquery'],
    ['start_time', 'bigint', 'Process start time'],
    ['watcher', 'integer', 'Whether the watcher process is enabled'],
  ]),
  mockOsqueryTable('processes', 'All running processes on the host.', [
    ['pid', 'bigint', 'Process identifier'],
    ['name', 'text', 'Process name'],
    ['path', 'text', 'Path to the executable'],
    ['cmdline', 'text', 'Complete command line'],
    ['cwd', 'text', 'Current working directory'],
    ['uid', 'bigint', 'User identifier'],
    ['gid', 'bigint', 'Group identifier'],
    ['parent', 'bigint', 'Parent process identifier'],
    ['state', 'text', 'Process state'],
    ['start_time', 'bigint', 'Process start time'],
    ['total_size', 'bigint', 'Total virtual memory size'],
    ['resident_size', 'bigint', 'Resident memory size'],
    ['threads', 'integer', 'Number of threads'],
  ]),
  mockOsqueryTable('users', 'Local user accounts present on the host.', [
    ['uid', 'bigint', 'User identifier'],
    ['gid', 'bigint', 'Primary group identifier'],
    ['username', 'text', 'Login name'],
    ['description', 'text', 'Account description'],
    ['directory', 'text', 'Home directory'],
    ['shell', 'text', 'Login shell'],
    ['uuid', 'text', 'Account UUID'],
    ['type', 'text', 'Account type'],
  ]),
  mockOsqueryTable('listening_ports', 'Processes with listening network sockets.', [
    ['pid', 'bigint', 'Process identifier'],
    ['port', 'integer', 'Listening port'],
    ['protocol', 'integer', 'Transport protocol'],
    ['family', 'integer', 'Network family'],
    ['address', 'text', 'Listening address'],
    ['fd', 'bigint', 'Socket file descriptor'],
    ['socket', 'bigint', 'Socket inode or handle'],
    ['path', 'text', 'UNIX socket path'],
  ]),
  mockOsqueryTable('interface_addresses', 'IP addresses assigned to network interfaces.', [
    ['interface', 'text', 'Interface name'],
    ['address', 'text', 'Assigned address'],
    ['mask', 'text', 'Network mask'],
    ['broadcast', 'text', 'Broadcast address'],
    ['point_to_point', 'text', 'Point-to-point destination'],
    ['type', 'text', 'Address type'],
    ['friendly_name', 'text', 'Human-readable interface name'],
  ]),
  mockOsqueryTable('system_info', 'Core hardware and operating-system identity.', [
    ['hostname', 'text', 'System hostname'],
    ['uuid', 'text', 'Hardware UUID'],
    ['cpu_type', 'text', 'CPU architecture'],
    ['cpu_brand', 'text', 'CPU brand string'],
    ['physical_memory', 'bigint', 'Installed physical memory'],
    ['hardware_vendor', 'text', 'Hardware vendor'],
    ['hardware_model', 'text', 'Hardware model'],
    ['hardware_serial', 'text', 'Hardware serial number'],
    ['computer_name', 'text', 'Configured computer name'],
    ['local_hostname', 'text', 'Local hostname'],
  ]),
  mockOsqueryTable('uptime', 'Time elapsed since the host last booted.', [
    ['days', 'integer', 'Whole days since boot'],
    ['hours', 'integer', 'Hour component'],
    ['minutes', 'integer', 'Minute component'],
    ['seconds', 'integer', 'Second component'],
    ['total_seconds', 'bigint', 'Total seconds since boot'],
  ]),
  mockOsqueryTable('logged_in_users', 'Users currently logged into the host.', [
    ['type', 'text', 'Login record type'],
    ['user', 'text', 'Username'],
    ['tty', 'text', 'Terminal device'],
    ['host', 'text', 'Remote host'],
    ['time', 'bigint', 'Login time'],
    ['pid', 'bigint', 'Login process identifier'],
  ]),
  mockOsqueryTable('deb_packages', 'Installed Debian packages and package metadata.', [
    ['name', 'text', 'Package name'],
    ['version', 'text', 'Installed version'],
    ['source', 'text', 'Source package'],
    ['size', 'bigint', 'Installed size'],
    ['arch', 'text', 'Package architecture'],
    ['status', 'text', 'Package status'],
    ['maintainer', 'text', 'Package maintainer'],
    ['section', 'text', 'Repository section'],
  ], ['linux']),
  mockOsqueryTable('launchd', 'macOS launch agents and daemons.', [
    ['name', 'text', 'Service name'],
    ['path', 'text', 'Property list path'],
    ['label', 'text', 'Launchd label'],
    ['program', 'text', 'Program path'],
    ['run_at_load', 'integer', 'Whether the service runs at load'],
    ['keep_alive', 'integer', 'Whether launchd keeps the service alive'],
    ['username', 'text', 'Configured user'],
    ['groupname', 'text', 'Configured group'],
  ], ['darwin']),
  mockOsqueryTable('programs', 'Installed Windows applications.', [
    ['name', 'text', 'Application name'],
    ['version', 'text', 'Installed version'],
    ['install_location', 'text', 'Install directory'],
    ['install_source', 'text', 'Installer source'],
    ['publisher', 'text', 'Software publisher'],
    ['install_date', 'text', 'Installation date'],
    ['identifying_number', 'text', 'Product identifier'],
  ], ['windows']),
];

const mockTags: AdminTag[] = [
  {
    id: 1,
    created_at: ago(90 * DAY),
    updated_at: ago(5 * DAY),
    name: 'production',
    description: 'Production workloads',
    color: '#3e63dd',
    icon: 'server',
    created_by: 'admin',
    custom_tag: '',
    auto_tag: false,
    environment_id: 1,
    tag_type: 0,
    cohort: true,
  },
  {
    id: 2,
    created_at: ago(60 * DAY),
    updated_at: ago(12 * DAY),
    name: 'engineering',
    description: 'Engineering endpoints',
    color: '#12a594',
    icon: 'code',
    created_by: 'admin',
    custom_tag: '',
    auto_tag: false,
    environment_id: 1,
    tag_type: 0,
    cohort: false,
  },
  {
    id: 3,
    created_at: ago(45 * DAY),
    updated_at: ago(2 * DAY),
    name: 'needs-attention',
    description: 'Endpoints requiring follow-up',
    color: '#e5484d',
    icon: 'alert-triangle',
    created_by: 'admin',
    custom_tag: '',
    auto_tag: true,
    environment_id: 1,
    tag_type: 1,
    cohort: false,
  },
  {
    id: 4,
    created_at: ago(30 * DAY),
    updated_at: ago(8 * DAY),
    name: 'finance',
    description: 'Finance team devices',
    color: '#8e4ec6',
    icon: 'briefcase',
    created_by: 'admin',
    custom_tag: '',
    auto_tag: false,
    environment_id: 1,
    tag_type: 0,
    cohort: false,
  },
];

function makeNode(
  id: number,
  hostname: string,
  platform: 'linux' | 'darwin' | 'windows',
  version: string,
  lastSeenHours: number,
  tags: AdminTag[],
  countryCode: string,
  risk: 'low' | 'medium' | 'high' = 'low',
): OsqueryNode {
  const platformVersion =
    platform === 'darwin' ? '15.6' : platform === 'windows' ? '11 24H2' : 'Ubuntu 24.04';
  const active = lastSeenHours < 72;
  return {
    id,
    created_at: ago((120 - id * 4) * DAY),
    updated_at: ago(lastSeenHours * HOUR),
    node_key: `mock-node-key-${id}`,
    uuid: `mock-node-${String(id).padStart(3, '0')}`,
    platform,
    platform_version: platformVersion,
    osquery_version: version,
    hostname,
    localname: hostname.split('.')[0],
    ip_address: `10.24.${Math.floor(id / 10)}.${20 + id}`,
    username: id % 2 === 0 ? 'svc-osquery' : 'local-user',
    osquery_user: 'root',
    environment: 'dev',
    cpu: platform === 'darwin' ? 'Apple M3 Pro' : 'Intel Xeon Gold 6338N',
    memory: String((16 + (id % 4) * 16) * 1024 * 1024 * 1024),
    hardware_serial: `OSCTRL-MOCK-${String(id).padStart(5, '0')}`,
    daemon_hash: `daemon-${id.toString(16).padStart(8, '0')}`,
    config_hash: `config-${(id * 17).toString(16).padStart(8, '0')}`,
    bytes_received: 245_000 + id * 187_321,
    last_seen: ago(lastSeenHours * HOUR),
    user_id: 1,
    environment_id: 1,
    extra_data: '',
    country_code: countryCode,
    tags,
    uptime: {
      days: 3 + id * 2,
      hours: (id * 3) % 24,
      minutes: id * 4,
      seconds: id,
      total_seconds: (3 + id * 2) * 86_400,
      last_seen: ago(Math.min(lastSeenHours, 4) * HOUR),
    },
    posture: { risk_level: risk },
    health: {
      status: !active ? 'offline' : risk === 'high' ? 'at_risk' : risk === 'medium' ? 'attention' : 'healthy',
      reason: !active
        ? 'No check-in within the active window'
        : risk === 'high'
          ? 'Critical posture controls failed'
          : risk === 'medium'
            ? 'Review recommended'
            : 'All signals normal',
      signals: !active ? ['stale_checkin'] : risk === 'low' ? ['recent_checkin'] : ['posture_findings'],
    },
    system_info: {
      system: {
        hardware_vendor: platform === 'darwin' ? 'Apple Inc.' : platform === 'windows' ? 'Dell Inc.' : 'Amazon EC2',
        hardware_model: platform === 'darwin' ? 'MacBookPro18,3' : 'Virtual Machine',
        hardware_serial: `OSCTRL-MOCK-${String(id).padStart(5, '0')}`,
        cpu_brand: platform === 'darwin' ? 'Apple M3 Pro' : 'Intel Xeon Gold 6338N',
        cpu_physical_cores: '8',
        cpu_logical_cores: '16',
        physical_memory: String((16 + (id % 4) * 16) * 1024 * 1024 * 1024),
        computer_name: hostname,
        local_hostname: hostname.split('.')[0],
      },
      os: {
        name: platform === 'darwin' ? 'macOS' : platform === 'windows' ? 'Windows 11' : 'Ubuntu',
        version: platformVersion,
        platform,
      },
      osquery: {
        version,
        build_platform: platform,
        config_valid: '1',
        start_time: String(Math.floor((now - (id + 3) * DAY) / 1000)),
      },
    },
  };
}

const mockNodes: OsqueryNode[] = [
  makeNode(1, 'api-prod-01.nyc', 'linux', '5.23.1', 0.1, [mockTags[0]], 'US'),
  makeNode(2, 'web-prod-02.iad', 'linux', '5.23.1', 0.4, [mockTags[0]], 'US'),
  makeNode(3, 'mbp-sloane', 'darwin', '5.22.0', 1.2, [mockTags[1]], 'US'),
  makeNode(4, 'fin-wks-044', 'windows', '5.21.0', 3, [mockTags[3]], 'GB', 'medium'),
  makeNode(5, 'buildkite-linux-07', 'linux', '5.23.1', 7, [mockTags[1]], 'DE'),
  makeNode(6, 'mbp-keiko', 'darwin', '5.23.1', 13, [mockTags[1]], 'JP'),
  makeNode(7, 'edge-prod-03.sfo', 'linux', '5.20.0', 28, [mockTags[0], mockTags[2]], 'US', 'high'),
  makeNode(8, 'design-win-12', 'windows', '5.22.0', 51, [], 'CA'),
  makeNode(9, 'worker-prod-18', 'linux', '5.23.1', 80, [mockTags[0], mockTags[2]], 'US', 'medium'),
  makeNode(10, 'mbp-archive', 'darwin', '5.19.0', 118, [mockTags[2]], 'AU', 'high'),
  makeNode(11, 'acct-win-07', 'windows', '5.21.0', 190, [mockTags[3], mockTags[2]], 'US', 'high'),
  makeNode(12, 'legacy-db-02', 'linux', '5.18.1', 264, [mockTags[0], mockTags[2]], 'NL', 'high'),
];

function makeQuery(
  id: number,
  name: string,
  query: string,
  state: 'active' | 'completed' | 'expired' | 'deleted',
  expected: number,
  executions: number,
  errors = 0,
  type = 'query',
): DistributedQuery {
  return {
    id,
    created_at: ago((id + 1) * HOUR),
    updated_at: ago(id * 17 * 60 * 1000),
    name,
    creator: id % 2 ? 'admin' : 'security-bot',
    query,
    expected,
    executions,
    errors,
    active: state === 'active',
    hidden: false,
    protected: false,
    completed: state === 'completed',
    deleted: state === 'deleted',
    expired: state === 'expired',
    type,
    path: type === 'carve' ? query : '',
    environment_id: 1,
    extra_data: '',
    expiration: ago(-12 * HOUR),
    target: expected === mockNodes.length ? 'all' : 'selected',
    targets: expected === mockNodes.length ? [{ type: 'environment', value: 'dev' }] : [{ type: 'platform', value: 'linux' }],
  };
}

let mockQueries: DistributedQuery[] = [
  makeQuery(1, 'incident-network-connections', 'SELECT * FROM process_open_sockets;', 'active', 12, 9, 1),
  makeQuery(2, 'browser-extension-audit', 'SELECT * FROM chrome_extensions;', 'active', 7, 4),
  makeQuery(3, 'unsigned-kernel-modules', 'SELECT * FROM kernel_modules WHERE signed = 0;', 'completed', 8, 8),
  makeQuery(4, 'launch-items-review', 'SELECT * FROM launchd;', 'completed', 2, 2),
  makeQuery(5, 'stale-local-admins', 'SELECT * FROM users WHERE uid = 0;', 'expired', 12, 10, 2),
];

let mockSavedQueries: SavedQuery[] = [
  { id: 1, created_at: ago(48 * DAY), updated_at: ago(4 * DAY), name: 'Listening ports', creator: 'admin', query: 'SELECT pid, port, protocol, address FROM listening_ports;', environment_id: 1 },
  { id: 2, created_at: ago(34 * DAY), updated_at: ago(8 * DAY), name: 'Recent user sessions', creator: 'admin', query: 'SELECT * FROM logged_in_users;', environment_id: 1 },
  { id: 3, created_at: ago(21 * DAY), updated_at: ago(2 * DAY), name: 'Unsigned binaries', creator: 'security-bot', query: 'SELECT path FROM signature WHERE signed = 0;', environment_id: 1 },
  { id: 4, created_at: ago(9 * DAY), updated_at: ago(9 * DAY), name: 'Disk encryption status', creator: 'admin', query: 'SELECT * FROM disk_encryption;', environment_id: 1 },
];

let mockCarves: DistributedQuery[] = [
  { ...makeQuery(21, 'collect-suspicious-binary', '/tmp/update-agent', 'active', 2, 1, 0, 'carve'), carve_status: 'ACTIVE' },
  { ...makeQuery(22, 'browser-artifacts', '/Users/*/Library/Application Support/Google/Chrome/Default/History', 'completed', 3, 3, 0, 'carve'), carve_status: 'COMPLETED' },
  { ...makeQuery(23, 'nginx-access-logs', '/var/log/nginx/access.log', 'expired', 4, 2, 1, 'carve'), carve_status: 'EXPIRED' },
];

const mockAudit: AuditLogsPagedResponse['items'] = [
  { id: 1, created_at: ago(4 * 60 * 1000), service: 'osctrl-api', username: 'admin', line: 'ran query incident-network-connections against 12 nodes', log_type: 4, severity: 1, source_ip: '127.0.0.1', environment_id: 1, env_uuid: 'dev' },
  { id: 2, created_at: ago(19 * 60 * 1000), service: 'osctrl-api', username: 'security-bot', line: 'tagged edge-prod-03.sfo with needs-attention', log_type: 6, severity: 1, source_ip: '10.24.0.8', environment_id: 1, env_uuid: 'dev' },
  { id: 3, created_at: ago(42 * 60 * 1000), service: 'osctrl-tls', username: 'node', line: 'node mbp-sloane enrolled successfully', log_type: 3, severity: 0, source_ip: '10.24.0.23', environment_id: 1, env_uuid: 'dev' },
  { id: 4, created_at: ago(2 * HOUR), service: 'osctrl-api', username: 'admin', line: 'created carve collect-suspicious-binary', log_type: 5, severity: 1, source_ip: '127.0.0.1', environment_id: 1, env_uuid: 'dev' },
  { id: 5, created_at: ago(5 * HOUR), service: 'osctrl-api', username: 'admin', line: 'updated environment dev configuration', log_type: 7, severity: 1, source_ip: '127.0.0.1', environment_id: 1, env_uuid: 'dev' },
  { id: 6, created_at: ago(9 * HOUR), service: 'osctrl-api', username: 'admin', line: 'logged in', log_type: 1, severity: 0, source_ip: '127.0.0.1', environment_id: 0 },
];

function activeNode(node: OsqueryNode) {
  return Date.parse(node.last_seen) >= now - 72 * HOUR;
}

function platformBucket(node: OsqueryNode) {
  if (node.platform === 'darwin') return 'darwin';
  if (node.platform === 'windows') return 'windows';
  if (node.platform === 'linux') return 'linux';
  return 'other';
}

function platformCounts(nodes: OsqueryNode[]) {
  const counts = { linux: 0, darwin: 0, windows: 0, other: 0 };
  for (const node of nodes) counts[platformBucket(node)] += 1;
  return counts;
}

function tileSeries(seed = 1, days = 2): NodeTileSeries {
  const length = Math.max(24, days * 24);
  const make = (offset: number, scale: number) =>
    Array.from({ length }, (_, index) => {
      const wave = Math.sin((index + seed + offset) / 4) + 1;
      return index % (9 + offset) === 0 ? 0 : Math.round(wave * scale + ((index + seed) % 3));
    });
  const config = make(1, 2);
  const status = make(2, 8);
  const result = make(3, 5);
  const query_read = make(4, 2);
  const query_write = make(5, 1);
  const enroll = make(6, 0.35);
  const total = status.map((_, index) =>
    status[index] + result[index] + config[index] + query_read[index] + query_write[index] + enroll[index],
  );
  return {
    start: new Date(now - (length - 1) * HOUR).toISOString(),
    bucket_seconds: 3600,
    enroll,
    config,
    status,
    result,
    query_read,
    query_write,
    total,
  };
}

const NODE_ACTIVITY_INTERVAL_HOURS: Record<string, number> = {
  '3h': 3,
  '6h': 6,
  '12h': 12,
  '1d': 24,
  '2d': 48,
  '3d': 72,
  '7d': 168,
};

function nodeActivity(seed = 1, hours = 24, bucketSeconds = 3600): NodeActivityBucket[] {
  const bucketMs = bucketSeconds * 1000;
  const length = Math.max(1, Math.round((hours * HOUR) / bucketMs));
  const lastBucketStart = Math.floor(now / bucketMs) * bucketMs;

  return Array.from({ length }, (_, index) => ({
    bucket_start: new Date(lastBucketStart - (length - 1 - index) * bucketMs).toISOString(),
    status: (index * seed) % 17,
    result: (index + seed) % 9,
    query: index % 6 === 0 ? 2 : 0,
    carve: index % 17 === 0 ? 1 : 0,
    config: index % 4 === 0 ? 1 : 0,
  }));
}

function page<T>(items: T[], search: URLSearchParams) {
  const pageNumber = Math.max(1, Number(search.get('page') ?? 1));
  const pageSize = Math.max(1, Number(search.get('page_size') ?? 50));
  const start = (pageNumber - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    page: pageNumber,
    page_size: pageSize,
    total_items: items.length,
    total_pages: Math.max(1, Math.ceil(items.length / pageSize)),
  };
}

function body<T>(init: RequestInit): Partial<T> {
  if (typeof init.body !== 'string') return {};
  try {
    return JSON.parse(init.body) as Partial<T>;
  } catch {
    return {};
  }
}

function hit(data: unknown): MockApiResult {
  return { matched: true, data };
}

function queryStateMatches(query: DistributedQuery, target: string) {
  if (target === 'all' || target === 'all-full') return true;
  if (target === 'active') return query.active;
  if (target === 'completed') return query.completed;
  if (target === 'expired') return query.expired;
  if (target === 'deleted') return query.deleted;
  if (target === 'hidden') return query.hidden;
  return true;
}

export function resolveMockApiRequest(path: string, init: RequestInit = {}): MockApiResult {
  if (!enabled) return { matched: false };

  const url = new URL(path, 'http://osctrl.mock');
  const pathname = url.pathname;
  const method = (init.method ?? 'GET').toUpperCase();

  if (method === 'GET' && pathname === '/api/v1/users/me') {
    return hit({
      id: 1,
      username: 'admin',
      fullname: 'Local preview',
      admin: true,
      service: false,
      created_at: ago(180 * DAY),
      updated_at: ago(2 * DAY),
      last_login: ago(18 * 60 * 1000),
      token_expire: new Date(now + 30 * DAY).toISOString(),
      environments: [],
    });
  }

  if (method === 'GET' && pathname === '/api/v1/osquery/tables') {
    return hit(mockOsqueryTables);
  }

  // Dashboard and activity surfaces.
  if (method === 'GET' && pathname === '/api/v1/stats') {
    const active = mockNodes.filter(activeNode).length;
    const activeQueries = mockQueries.filter((query) => query.active).length;
    const activeCarves = mockCarves.filter((carve) => carve.active).length;
    const stats: StatsResponse = {
      total_nodes: mockNodes.length,
      active_nodes: active,
      inactive_nodes: mockNodes.length - active,
      inactive_hours: 72,
      total_active_queries: activeQueries,
      total_active_carves: activeCarves,
      platform_counts: platformCounts(mockNodes),
      environments: [{
        uuid: 'dev',
        name: 'dev',
        active,
        inactive: mockNodes.length - active,
        total: mockNodes.length,
        active_queries: activeQueries,
        active_carves: activeCarves,
        platform_counts: platformCounts(mockNodes),
      }],
    };
    return hit(stats);
  }
  if (method === 'GET' && pathname === '/api/v1/stats/osquery-versions') {
    const counts = new Map<string, number>();
    for (const node of mockNodes) counts.set(node.osquery_version, (counts.get(node.osquery_version) ?? 0) + 1);
    return hit([...counts].map(([version, count]) => ({ version, count })).sort((a, b) => b.count - a.count));
  }
  if (method === 'GET' && pathname.includes('/api/v1/stats/activity/env-tiles/')) {
    return hit(tileSeries(4, Number(url.searchParams.get('days') ?? 2)));
  }
  if (method === 'GET' && pathname.includes('/api/v1/stats/activity/node-tiles-batch/')) {
    const uuids = (url.searchParams.get('uuids') ?? '').split(',').filter(Boolean);
    const days = Number(url.searchParams.get('days') ?? 2);
    return hit(Object.fromEntries(uuids.map((uuid, index) => [uuid, tileSeries(index + 1, days)])));
  }
  if (method === 'GET' && pathname.includes('/api/v1/stats/activity/node-tiles/')) {
    const uuid = pathname.split('/').at(-1) ?? '';
    const seed = mockNodes.findIndex((node) => node.uuid === uuid) + 1;
    return hit(tileSeries(Math.max(seed, 1), Number(url.searchParams.get('days') ?? 2)));
  }
  if (method === 'GET' && pathname.includes('/api/v1/stats/activity/node-batch/')) {
    const uuids = (url.searchParams.get('uuids') ?? '').split(',').filter(Boolean);
    return hit(Object.fromEntries(uuids.map((uuid, index) => [uuid, nodeActivity(index + 1)])));
  }
  if (method === 'GET' && pathname.includes('/api/v1/stats/activity/node/')) {
    const uuid = pathname.split('/').at(-1) ?? '';
    const seed = mockNodes.findIndex((node) => node.uuid === uuid) + 1;
    const hours = NODE_ACTIVITY_INTERVAL_HOURS[url.searchParams.get('interval') ?? '1d'] ?? 24;
    const requestedBucketSeconds = Number(url.searchParams.get('bucket_seconds') ?? 3600);
    const bucketSeconds = Number.isFinite(requestedBucketSeconds) && requestedBucketSeconds > 0
      ? requestedBucketSeconds
      : 3600;
    return hit(nodeActivity(Math.max(seed, 1), hours, bucketSeconds));
  }

  // Nodes list, detail, logs, and posture.
  const nodeDetail = pathname.match(/^\/api\/v1\/nodes\/[^/]+\/node\/([^/]+)$/);
  if (method === 'GET' && nodeDetail) {
    return hit(mockNodes.find((node) => node.uuid === decodeURIComponent(nodeDetail[1])) ?? mockNodes[0]);
  }
  const nodeList = pathname.match(/^\/api\/v1\/nodes\/([^/]+)$/);
  if (method === 'GET' && nodeList) {
    const q = (url.searchParams.get('q') ?? '').toLowerCase();
    const status = url.searchParams.get('status');
    const platform = url.searchParams.get('platform');
    const filtered = mockNodes.filter((node) => {
      if (q && !`${node.hostname} ${node.localname} ${node.ip_address} ${node.uuid}`.toLowerCase().includes(q)) return false;
      if (status === 'active' && !activeNode(node)) return false;
      if (status === 'inactive' && activeNode(node)) return false;
      if (platform && platformBucket(node) !== platform) return false;
      return true;
    });
    return hit(page(filtered, url.searchParams) satisfies NodesPagedResponse);
  }
  const nodeLogs = pathname.match(/^\/api\/v1\/logs\/(status|result)\/[^/]+\/([^/]+)$/);
  if (method === 'GET' && nodeLogs) {
    const type = nodeLogs[1] as 'status' | 'result';
    const uuid = decodeURIComponent(nodeLogs[2]);
    const items = type === 'status'
      ? [
          { created_at: ago(8 * 60 * 1000), severity: '0', filename: 'scheduler.cpp', line: 'Scheduled query completed successfully', message: 'schedule executed' },
          { created_at: ago(42 * 60 * 1000), severity: '1', filename: 'watcher.cpp', line: 'Performance limit approached', message: 'watchdog memory threshold at 82%' },
        ]
      : [
          { created_at: ago(12 * 60 * 1000), name: 'uptime', action: 'added', columns: { days: '14', hours: '6', minutes: '22' } },
          { created_at: ago(65 * 60 * 1000), name: 'listening_ports', action: 'added', columns: { pid: '912', port: '443', protocol: '6' } },
        ];
    return hit({ items, type, uuid, env: 'dev', limit: 100 });
  }
  if (method === 'GET' && /\/posture\/score$/.test(pathname)) {
    const uuid = pathname.split('/').at(-3) ?? mockNodes[0].uuid;
    const score: PostureScore = {
      node_uuid: uuid,
      timestamp: ago(2 * HOUR),
      total_score: 24,
      risk_level: 'medium',
      pass_count: 8,
      warn_count: 2,
      fail_count: 1,
      controls: [
        { category: 'hardening', control_id: 'OSCTRL-1', framework: 'CIS', title: 'Disk encryption enabled', description: 'System disk should be encrypted.', status: 'pass', severity: 'high', score: 0, max_score: 20, detail: 'Encryption is enabled.' },
        { category: 'access', control_id: 'OSCTRL-2', framework: 'CIS', title: 'No unexpected local admins', description: 'Administrative access should be constrained.', status: 'warn', severity: 'medium', score: 8, max_score: 12, detail: 'One account requires review.' },
      ],
    };
    return hit(score);
  }
  if (method === 'GET' && /\/posture$/.test(pathname)) {
    const uuid = pathname.split('/').at(-2) ?? mockNodes[0].uuid;
    const posture: NodePosture[] = [
      { id: 1, created_at: ago(3 * DAY), updated_at: ago(2 * HOUR), node_uuid: uuid, environment: 'dev', category: 'uptime', query_name: 'osctrl:posture:uptime', row_count: 1, summary: '14 days, 6 hours', first_seen: ago(3 * DAY), last_seen: ago(2 * HOUR) },
      { id: 2, created_at: ago(3 * DAY), updated_at: ago(2 * HOUR), node_uuid: uuid, environment: 'dev', category: 'disk_encryption', query_name: 'osctrl:posture:disk_encryption', row_count: 1, summary: 'encrypted', first_seen: ago(3 * DAY), last_seen: ago(2 * HOUR) },
    ];
    return hit(posture);
  }
  if (method === 'POST' && /\/api\/v1\/nodes\/[^/]+\/(delete|tag)$/.test(pathname)) {
    return hit({ message: 'Mock action completed' });
  }

  // Distributed queries and their results.
  const queryList = pathname.match(/^\/api\/v1\/queries\/[^/]+\/list\/([^/]+)$/);
  if (method === 'GET' && queryList) {
    const target = decodeURIComponent(queryList[1]);
    const q = (url.searchParams.get('q') ?? '').toLowerCase();
    const filtered = mockQueries.filter((query) => queryStateMatches(query, target) && (!q || `${query.name} ${query.creator} ${query.query}`.toLowerCase().includes(q)));
    return hit(page(filtered, url.searchParams));
  }
  const queryResults = pathname.match(/^\/api\/v1\/queries\/[^/]+\/results\/([^/]+)$/);
  if (method === 'GET' && queryResults) {
    const name = decodeURIComponent(queryResults[1]);
    const items = mockNodes.slice(0, 7).map((node, index) => ({
      id: index + 1,
      created_at: ago((index + 1) * 4 * 60 * 1000),
      uuid: node.uuid,
      environment: 'dev',
      name,
      data: JSON.stringify({ hostname: node.hostname, platform: node.platform, pid: 400 + index, path: `/usr/bin/mock-${index}` }),
      status: index === 5 ? 1 : 0,
    }));
    return hit({ ...page(items, url.searchParams), since: ago(HOUR) } satisfies QueryResultsResponse);
  }
  const queryAction = pathname.match(/^\/api\/v1\/queries\/[^/]+\/(delete|expire|complete)\/([^/]+)$/);
  if (method === 'POST' && queryAction) {
    const name = decodeURIComponent(queryAction[2]);
    mockQueries = mockQueries.map((query) => query.name === name ? { ...query, active: false, [queryAction[1] === 'delete' ? 'deleted' : queryAction[1] === 'expire' ? 'expired' : 'completed']: true } : query);
    return hit({ message: 'Mock query updated' });
  }
  const queryDetail = pathname.match(/^\/api\/v1\/queries\/[^/]+\/([^/]+)$/);
  if (method === 'GET' && queryDetail) {
    return hit(mockQueries.find((query) => query.name === decodeURIComponent(queryDetail[1])) ?? mockQueries[0]);
  }
  if (method === 'POST' && /^\/api\/v1\/queries\/[^/]+$/.test(pathname)) {
    return hit({ query_name: 'mock-live-query' });
  }

  // Saved queries, including in-memory CRUD for review interactions.
  const savedPath = pathname.match(/^\/api\/v1\/saved-queries\/[^/]+(?:\/([^/]+))?$/);
  if (savedPath) {
    const name = savedPath[1] ? decodeURIComponent(savedPath[1]) : undefined;
    if (method === 'GET' && !name) {
      const q = (url.searchParams.get('q') ?? '').toLowerCase();
      return hit(page(mockSavedQueries.filter((item) => !q || `${item.name} ${item.creator} ${item.query}`.toLowerCase().includes(q)), url.searchParams));
    }
    if (method === 'POST' && !name) {
      const request = body<{ name: string; query: string }>(init);
      const item: SavedQuery = { id: Date.now(), created_at: new Date().toISOString(), updated_at: new Date().toISOString(), name: request.name ?? 'Untitled query', creator: 'admin', query: request.query ?? 'SELECT 1;', environment_id: 1 };
      mockSavedQueries = [item, ...mockSavedQueries];
      return hit(item);
    }
    if (method === 'PATCH' && name) {
      const request = body<{ query: string }>(init);
      mockSavedQueries = mockSavedQueries.map((item) => item.name === name ? { ...item, query: request.query ?? item.query, updated_at: new Date().toISOString() } : item);
      return hit(mockSavedQueries.find((item) => item.name === name));
    }
    if (method === 'DELETE' && name) {
      mockSavedQueries = mockSavedQueries.filter((item) => item.name !== name);
      return hit({ message: 'Mock saved query deleted' });
    }
  }

  // Carves and carve detail.
  const carvePath = pathname.match(/^\/api\/v1\/carves\/[^/]+(?:\/([^/]+))?$/);
  if (carvePath) {
    const name = carvePath[1] ? decodeURIComponent(carvePath[1]) : undefined;
    if (method === 'GET' && !name) {
      const target = url.searchParams.get('target') ?? 'all';
      const q = (url.searchParams.get('q') ?? '').toLowerCase();
      return hit(page(mockCarves.filter((carve) => queryStateMatches(carve, target) && (!q || `${carve.name} ${carve.path}`.toLowerCase().includes(q))), url.searchParams));
    }
    if (method === 'GET' && name) {
      const query = mockCarves.find((carve) => carve.name === name) ?? mockCarves[0];
      const detail: CarveDetail = {
        query,
        files: mockNodes.slice(0, Math.min(query.executions, 3)).map((node, index) => ({
          carve_id: `mock-carve-${index + 1}`,
          session_id: `session-${index + 1}`,
          uuid: node.uuid,
          path: query.path,
          status: query.completed ? 'COMPLETED' : 'PENDING',
          carve_size: 1_240_000 + index * 820_000,
          block_size: 8192,
          total_blocks: 152 + index * 100,
          completed_blocks: query.completed ? 152 + index * 100 : 94,
          archived: query.completed,
          created_at: query.created_at,
          completed_at: query.completed ? query.updated_at : '',
        })),
      };
      return hit(detail);
    }
    if (method === 'POST' && !name) return hit({ query_name: 'mock-carve' });
  }
  const carveAction = pathname.match(/^\/api\/v1\/carves\/[^/]+\/(delete|expire|complete)\/([^/]+)$/);
  if (method === 'POST' && carveAction) {
    mockCarves = mockCarves.map((carve) => carve.name === decodeURIComponent(carveAction[2]) ? { ...carve, active: false, [carveAction[1] === 'delete' ? 'deleted' : carveAction[1] === 'expire' ? 'expired' : 'completed']: true } : carve);
    return hit({ message: 'Mock carve updated' });
  }

  // Tags and audit activity.
  if (method === 'GET' && /^\/api\/v1\/tags(?:\/[^/]+)?$/.test(pathname)) return hit(mockTags);
  if (method === 'POST' && /^\/api\/v1\/tags\/[^/]+\/(add|edit|remove)$/.test(pathname)) return hit({ data: 'Mock tag action completed' });
  if (method === 'GET' && pathname === '/api/v1/audit-logs') {
    const qType = url.searchParams.get('type');
    const filtered = qType ? mockAudit.filter((item) => item.log_type === Number(qType)) : mockAudit;
    return hit(page(filtered, url.searchParams));
  }

  return { matched: false };
}
