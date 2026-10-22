import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { NodeDetailPage } from './NodeDetailPage';
import type { NodeConfig, NodeExtensions, NodeFlags, NodePosture, OsqueryNode, SavedQueriesPagedResponse, AdminTag, PostureScore } from '$/api/types';
import type { NodeActivityBucket, NodeTileSeries } from '$/api/stats';
import type { Features } from '$/api/features';

const mockGetNode = vi.fn<() => Promise<OsqueryNode>>();
const mockListNodeLogs = vi.fn<() => Promise<unknown>>();
const mockDeleteNode = vi.fn<() => Promise<{ message: string }>>();
const mockGetNodeConfig = vi.fn<() => Promise<NodeConfig>>();
const mockGetNodeFlags = vi.fn<() => Promise<NodeFlags>>();
const mockGetNodeExtensions = vi.fn<() => Promise<NodeExtensions>>();
const mockGetNodePosture = vi.fn<() => Promise<NodePosture[]>>();
const mockGetNodePostureScore = vi.fn<() => Promise<PostureScore>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();
const mockListEnvironments = vi.fn<() => Promise<Array<{ id: number; name: string; uuid: string }>>>();
const mockGetNodeActivity = vi.fn<() => Promise<NodeActivityBucket[]>>();
const mockGetNodeActivityTiles = vi.fn<() => Promise<NodeTileSeries>>();
const mockGetInactiveHours = vi.fn();
const mockGetFeatures = vi.fn<() => Promise<Features>>();
const mockListSavedQueries = vi.fn<() => Promise<SavedQueriesPagedResponse>>();
const mockRunQuery = vi.fn<() => Promise<{ query_name: string }>>();
const mockRunCarve = vi.fn<() => Promise<{ query_name: string }>>();
const mockListEnvTags = vi.fn<() => Promise<AdminTag[]>>();
const mockTagNode = vi.fn<() => Promise<{ message: string }>>();

vi.mock('$/api/nodes', () => ({
  getNode: (...args: unknown[]) => mockGetNode(...(args as [])),
  listNodeLogs: (...args: unknown[]) => mockListNodeLogs(...(args as [])),
  deleteNode: (...args: unknown[]) => mockDeleteNode(...(args as [])),
  getNodeConfig: (...args: unknown[]) => mockGetNodeConfig(...(args as [])),
  getNodeFlags: (...args: unknown[]) => mockGetNodeFlags(...(args as [])),
  getNodePosture: (...args: unknown[]) => mockGetNodePosture(...(args as [])),
  getNodePostureScore: (...args: unknown[]) => mockGetNodePostureScore(...(args as [])),
}));

vi.mock('$/api/extensions', () => ({
  getNodeExtensions: (...args: unknown[]) => mockGetNodeExtensions(...(args as [])),
}));

vi.mock('$/api/users', () => ({
  getMe: (...args: unknown[]) => mockGetMe(...(args as [])),
}));

vi.mock('$/api/environments', () => ({
  getEnvironmentInactiveHours: (...args: unknown[]) => mockGetInactiveHours(...args),
  listEnvironments: (...args: unknown[]) => mockListEnvironments(...(args as [])),
}));

vi.mock('$/api/stats', async () => {
  const actual = await vi.importActual<typeof import('$/api/stats')>('$/api/stats');
  return {
    ...actual,
    getNodeActivity: (...args: unknown[]) => mockGetNodeActivity(...(args as [])),
    getNodeActivityTiles: (...args: unknown[]) => mockGetNodeActivityTiles(...(args as [])),
  };
});

vi.mock('$/api/features', () => ({
  getFeatures: (...args: unknown[]) => mockGetFeatures(...(args as [])),
}));

vi.mock('$/api/saved-queries', () => ({
  listSavedQueries: (...args: unknown[]) => mockListSavedQueries(...(args as [])),
}));

vi.mock('$/api/queries', () => ({
  runQuery: (...args: unknown[]) => mockRunQuery(...(args as [])),
}));

vi.mock('$/api/carves', () => ({
  runCarve: (...args: unknown[]) => mockRunCarve(...(args as [])),
}));

const mockCreateAlertRule = vi.fn();
const mockApplyAlerts = vi.fn();
const mockListAlertChannels = vi.fn();
const mockListAlertRules = vi.fn();
vi.mock('$/api/alerts', () => ({
  // Only forward the first argument: react-query calls mutationFn with
  // (variables, context) and the assertions compare just the payload.
  createAlertRule: (first: unknown) => mockCreateAlertRule(first),
  applyAlerts: (first: unknown) => mockApplyAlerts(first),
  listAlertChannels: (first: unknown) => mockListAlertChannels(first),
  listAlertRules: (first: unknown) => mockListAlertRules(first),
}));

vi.mock('$/api/tags', () => ({
  listEnvTags: (...args: unknown[]) => mockListEnvTags(...(args as [])),
  tagNode: (...args: unknown[]) => mockTagNode(...(args as [])),
}));

vi.mock('./NodeConfigTab', () => ({
  NodeConfigTab: () => <div data-testid="config-panel" />,
}));

vi.mock('./NodeFileExplorerTab', () => ({
  NodeFileExplorerTab: () => <div data-testid="file-explorer-panel" />,
}));

vi.mock('$/features/vulnerabilities/NodeVulnerabilitiesTab', () => ({
  NodeVulnerabilitiesTab: () => <div data-testid="vulnerabilities-panel" />,
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
  getCsrfToken: () => 'test-csrf',
  setCsrfToken: vi.fn(),
  AuthError: class AuthError extends Error {
    readonly status = 401;
    constructor() {
      super('Unauthorized');
    }
  },
  ApiError: class ApiError extends Error {
    constructor(
      msg: string,
      public status: number,
      public code?: string,
    ) {
      super(msg);
    }
  },
}));

function makeNode(overrides: Partial<OsqueryNode> = {}): OsqueryNode {
  return {
    id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    node_key: 'node-key-123',
    uuid: 'abc12345-0000-0000-0000-000000000001',
    platform: 'linux',
    platform_version: '22.04',
    osquery_version: '5.11.0',
    hostname: 'web-server-01',
    localname: 'web01',
    ip_address: '10.0.0.1',
    username: 'admin',
    osquery_user: 'root',
    environment: 'test-env',
    cpu: 'Intel Xeon',
    memory: '17179869184',
    hardware_serial: 'SN001',
    daemon_hash: 'abc',
    config_hash: 'def',
    bytes_received: 1024,
    last_seen: new Date(Date.now() - 60_000).toISOString(),
    user_id: 1,
    environment_id: 1,
    extra_data: '',
    ...overrides,
  };
}

function makeNodeConfig(overrides: Partial<NodeConfig> = {}): NodeConfig {
  return {
    environment: '{}',
    override: '',
    applied: '{}',
    expires_at: null,
    expired: false,
    updated_by: '',
    updated_at: null,
    ...overrides,
  };
}

function makeNodeFlags(overrides: Partial<NodeFlags> = {}): NodeFlags {
  return {
    environment: '--verbose=false',
    override: '',
    applied: '--verbose=false',
    expires_at: null,
    expired: false,
    updated_by: '',
    updated_at: null,
    conflicts: [],
    osctrld: null,
    ...overrides,
  };
}

function makeNodeExtensions(overrides: Partial<NodeExtensions> = {}): NodeExtensions {
  return { effective: [], assignments: [], status: [], library: null, ...overrides };
}

function hostAssignment(o: Partial<NonNullable<NodeExtensions['assignments']>[number]> = {}) {
  return {
    extension_id: 9,
    name: 'cmd-ext',
    expires_at: null,
    expired: false,
    created_by: 'root',
    created_at: '2026-10-03T10:00:00Z',
    ...o,
  };
}

function extStatus(result: string, o: Partial<NonNullable<NodeExtensions['status']>[number]> = {}) {
  return { name: 'cmd-ext', sha256: 'bb', result, error: '', at: null, reported_at: '2026-10-03T11:00:00Z', ...o };
}

function makeActivityBuckets(): NodeActivityBucket[] {
  return [
    {
      bucket_start: '2026-06-17T10:00:00Z',
      status: 3,
      result: 1,
      query: 0,
      carve: 0,
      config: 0,
    },
    {
      bucket_start: '2026-06-17T11:00:00Z',
      status: 1,
      result: 2,
      query: 1,
      carve: 0,
      config: 0,
    },
  ];
}

function makeSavedQueries(): SavedQueriesPagedResponse {
  return {
    items: [
      {
        id: 1,
        created_at: '2026-07-26T10:00:00Z',
        updated_at: '2026-07-26T10:00:00Z',
        name: 'process inventory',
        creator: 'alice',
        query: 'select * from processes;',
        environment_id: 1,
      },
    ],
    page: 1,
    page_size: 50,
    total_items: 1,
    total_pages: 1,
  };
}

function makeTags(): AdminTag[] {
  return [
    {
      id: 1,
      created_at: '2026-07-26T10:00:00Z',
      updated_at: '2026-07-26T10:00:00Z',
      name: 'prod',
      description: 'Production',
      color: '#2ecc71',
      icon: 'tag',
      created_by: 'alice',
      custom_tag: 'tag',
      auto_tag: false,
      environment_id: 1,
      tag_type: 6,
      cohort: true,
    },
  ];
}

function makeTestRouter(initialPath = '/_app/env/test-env/nodes/abc12345-0000-0000-0000-000000000001') {
  const rootRoute = createRootRoute({ component: Outlet });

  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });

  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });

  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <div data-testid="nodes-page">nodes</div>,
  });

  const nodeDetailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes/$uuid',
    component: NodeDetailPage,
  });

  const queryNewRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries/new',
    component: () => <div data-testid="query-new-page">query new</div>,
  });

  const queryDetailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries/$name',
    component: () => <div data-testid="query-detail-page">query detail</div>,
  });

  const carveDetailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'carves/$name',
    component: () => <div data-testid="carve-detail-page">carve detail</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([nodesRoute, nodeDetailRoute, queryNewRoute, queryDetailRoute, carveDetailRoute]),
    ]),
  ]);

  const history = createMemoryHistory({ initialEntries: [initialPath] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  let ui: ReturnType<typeof render>;
  act(() => {
    ui = render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  });
  return ui!;
}

describe('NodeDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetNode.mockResolvedValue(makeNode());
    mockListNodeLogs.mockResolvedValue({
      items: [],
      type: 'status',
      uuid: 'abc12345-0000-0000-0000-000000000001',
      env: 'test-env',
      limit: 100,
    });
    mockDeleteNode.mockResolvedValue({ message: 'ok' });
    mockGetNodePosture.mockResolvedValue([]);
    mockGetNodeConfig.mockResolvedValue(makeNodeConfig());
    mockGetNodeFlags.mockResolvedValue(makeNodeFlags());
    mockGetNodeExtensions.mockResolvedValue(makeNodeExtensions());
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    mockListAlertRules.mockResolvedValue([]);
    mockListEnvironments.mockResolvedValue([{ id: 5, name: 'test-env', uuid: 'env-uuid-1' }]);
    mockGetNodeActivity.mockResolvedValue(makeActivityBuckets());
    mockGetNodeActivityTiles.mockResolvedValue({
      start: new Date(Date.now() - 23 * 3600_000).toISOString(),
      bucket_seconds: 3600,
      enroll: [],
      status_error: [],
      config: [],
      status: [],
      result: [],
      query_read: [],
      query_write: [],
      total: [],
    });
    mockGetInactiveHours.mockResolvedValue({ override_hours: null, inactive_hours: 72, source: 'default' });
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false });
    mockGetNodePostureScore.mockResolvedValue({
      node_uuid: 'abc12345-0000-0000-0000-000000000001',
      timestamp: '2026-07-16T09:05:00Z',
      total_score: 0,
      risk_level: 'low',
      controls: [],
      pass_count: 0,
      warn_count: 0,
      fail_count: 0,
    });
    mockListSavedQueries.mockResolvedValue(makeSavedQueries());
    mockRunQuery.mockResolvedValue({ query_name: 'query-123' });
    mockRunCarve.mockResolvedValue({ query_name: 'carve-123' });
    mockListEnvTags.mockResolvedValue(makeTags());
    mockTagNode.mockResolvedValue({ message: 'ok' });
    mockListAlertChannels.mockResolvedValue([]);
    mockCreateAlertRule.mockResolvedValue({ id: 1, name: 'r' });
    mockApplyAlerts.mockResolvedValue({ message: 'ok' });
  });

  it('shows node activity in the default details view and removes the separate activity tab', async () => {
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('tab', { name: 'Activity' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Details' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('heading', { name: /Node activity/i })).toBeInTheDocument();
    const activePips = screen.getAllByRole('img', { name: 'active' });
    expect(activePips).toHaveLength(1);
    expect(activePips[0]).toHaveClass('pip-live');

    await waitFor(() => {
      expect(mockGetNodeActivity).toHaveBeenCalledWith(
        'test-env',
        'abc12345-0000-0000-0000-000000000001',
        '6h',
        450,
      );
    });
  });

  it('keeps a node active when it was seen within the backend default 72 hour window', async () => {
    mockGetNode.mockResolvedValue(
      makeNode({ last_seen: new Date(Date.now() - 48 * 3600_000).toISOString() }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument();
    });
  });

  it.each([24, 168])('uses the environment threshold %s in the detail status', async (hours) => {
    mockGetInactiveHours.mockResolvedValue({ override_hours: hours, inactive_hours: hours, source: 'environment' });
    mockGetNode.mockResolvedValue(makeNode({ last_seen: new Date(Date.now() - 48 * 3600_000).toISOString() }));
    renderWithProviders(makeTestRouter());
    expect(await screen.findByText(hours === 24 ? 'Inactive' : 'Active')).toBeInTheDocument();
    expect(mockGetInactiveHours).toHaveBeenCalledWith('test-env');
  });

  it('copies the node key and refreshes the node view', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', {
      ...navigator,
      clipboard: { writeText },
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Copy node key' }));

    expect(writeText).toHaveBeenCalledWith('node-key-123');
    expect(screen.getByText('Copied node key')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Refresh node' }));

    await waitFor(() => {
      expect(mockGetNode).toHaveBeenCalledTimes(2);
    });

    vi.unstubAllGlobals();
  });

  // The errors row sits alongside status/result/query/config in the node
  // activity heatmap, with the count stated in text so it is not colour-only.
  it('shows an errors row in the node activity heatmap', async () => {
    // The Redis series is aligned onto the DB buckets by timestamp, so the
    // fixture has to start where makeActivityBuckets() does or the errors
    // land outside the window and correctly read zero.
    mockGetNodeActivityTiles.mockResolvedValue({
      start: '2026-06-17T10:00:00Z',
      bucket_seconds: 3600,
      enroll: [0, 0],
      status_error: [3, 0],
      config: [0, 0],
      status: [9, 0],
      result: [0, 0],
      query_read: [0, 0],
      query_write: [0, 0],
      total: [9, 0],
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByLabelText('Node activity heatmap')).toBeInTheDocument();
    });
    const heatmap = screen.getByLabelText('Node activity heatmap');
    // The row label, alongside status/result/query/config.
    expect(within(heatmap).getAllByText('errors').length).toBeGreaterThan(0);
    // And the count stated in the header, not left to the colour alone.
    expect(heatmap.textContent).toContain('3 errors');
  });

  it('shows posture data for the selected node', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetNodePosture.mockResolvedValue([
      {
        id: 10,
        created_at: '2026-07-16T09:00:00Z',
        updated_at: '2026-07-16T09:05:00Z',
        node_uuid: 'abc12345-0000-0000-0000-000000000001',
        environment: 'test-env',
        category: 'firewall',
        query_name: 'osctrl:posture:firewall',
        row_count: 2,
        summary: JSON.stringify([{ enabled: '1', profile: 'domain' }]),
        first_seen: '2026-07-16T09:00:00Z',
        last_seen: '2026-07-16T09:05:00Z',
      },
    ]);

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: 'Posture' }));

    await waitFor(() => {
      expect(mockGetNodePosture).toHaveBeenCalledWith(
        'test-env',
        'abc12345-0000-0000-0000-000000000001',
      );
    });

    expect(screen.getByRole('button', { name: /firewall/i })).toHaveTextContent('2 rows');

    await user.click(screen.getByRole('button', { name: /firewall/i }));

    expect(screen.getByText('enabled:')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('profile:')).toBeInTheDocument();
    expect(screen.getByText('domain')).toBeInTheDocument();
  });

  it('renders posture score when controls is null', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetNodePosture.mockResolvedValue([
      {
        id: 10,
        created_at: '2026-07-16T09:00:00Z',
        updated_at: '2026-07-16T09:05:00Z',
        node_uuid: 'abc12345-0000-0000-0000-000000000001',
        environment: 'test-env',
        category: 'firewall',
        query_name: 'osctrl:posture:firewall',
        row_count: 1,
        summary: JSON.stringify([{ enabled: '1' }]),
        first_seen: '2026-07-16T09:00:00Z',
        last_seen: '2026-07-16T09:05:00Z',
      },
    ]);
    mockGetNodePostureScore.mockResolvedValue({
      node_uuid: 'abc12345-0000-0000-0000-000000000001',
      timestamp: '2026-07-16T09:05:00Z',
      total_score: 0,
      risk_level: 'low',
      controls: null,
      pass_count: 0,
      warn_count: 0,
      fail_count: 0,
    } as unknown as PostureScore);

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: 'Posture' }));

    expect(await screen.findByText('Risk score')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /firewall/i })).toBeInTheDocument();
  });

  it('recomputes the risk score live when a control is unchecked', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetNodePosture.mockResolvedValue([
      {
        id: 11,
        created_at: '2026-07-16T09:00:00Z',
        updated_at: '2026-07-16T09:05:00Z',
        node_uuid: 'abc12345-0000-0000-0000-000000000001',
        environment: 'test-env',
        category: 'disk_encryption',
        query_name: 'osctrl:posture:disk_encryption',
        row_count: 1,
        summary: JSON.stringify([{ encrypted: '0' }]),
        first_seen: '2026-07-16T09:00:00Z',
        last_seen: '2026-07-16T09:05:00Z',
      },
    ]);
    // earned = 30 (fail) + 0 (pass) = 30, possible = 30 + 5 = 35 -> 86.
    // total_score/risk_level here match what the server's own aggregation
    // would produce for these two controls, since the SPA always recomputes
    // from each control's score/max_score rather than trusting this field
    // verbatim — see recomputePostureScore.
    mockGetNodePostureScore.mockResolvedValue({
      node_uuid: 'abc12345-0000-0000-0000-000000000001',
      timestamp: '2026-07-16T09:05:00Z',
      total_score: 86,
      risk_level: 'critical',
      controls: [
        {
          category: 'disk_encryption',
          control_id: 'A.8.24',
          framework: 'ISO27001',
          title: 'Disk encryption at rest',
          description: '',
          status: 'fail',
          severity: 'critical',
          score: 30,
          max_score: 30,
          detail: 'Disk is not encrypted',
        },
        {
          category: 'patches',
          control_id: 'A.8.9',
          framework: 'ISO27001',
          title: 'Patch management',
          description: '',
          status: 'pass',
          severity: 'low',
          score: 0,
          max_score: 5,
          detail: 'Up to date',
        },
      ],
      pass_count: 1,
      warn_count: 0,
      fail_count: 1,
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('tab', { name: 'Posture' }));

    // Starts identical to the server score: both checks counted.
    await waitFor(() => {
      expect(screen.getByText('86')).toBeInTheDocument();
    });
    expect(screen.getByText('Critical', { selector: 'span' })).toBeInTheDocument();

    // Uncheck the failing critical control — only the passing low-severity
    // one remains, so the score drops to 0 and the level to low. No new
    // network request: this is a pure client-side recompute.
    await user.click(screen.getByRole('checkbox', { name: /disk encryption at rest/i }));

    await waitFor(() => {
      expect(screen.getByText('0')).toBeInTheDocument();
    });
    expect(screen.getByText('Low', { selector: 'span' })).toBeInTheDocument();
    expect(screen.getByText('1/2 checks counted')).toBeInTheDocument();
    expect(mockGetNodePostureScore).toHaveBeenCalledTimes(1);

    // Re-checking it restores the original score.
    await user.click(screen.getByRole('checkbox', { name: /disk encryption at rest/i }));
    await waitFor(() => {
      expect(screen.getByText('86')).toBeInTheDocument();
    });
    expect(screen.queryByText('1/2 checks counted')).not.toBeInTheDocument();
  });

  it('hides posture tab while the posture feature is disabled', async () => {
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('tab', { name: 'Posture' })).not.toBeInTheDocument();
    expect(mockGetNodePosture).not.toHaveBeenCalled();
  });

  it('hides posture query results from the result logs tab', async () => {
    const user = userEvent.setup();
    mockListNodeLogs.mockResolvedValue({
      items: [
        {
          created_at: '2026-07-16T09:05:00Z',
          name: 'osctrl:posture:firewall',
          action: 'added',
          columns: '{"enabled":"1"}',
        },
        {
          created_at: '2026-07-16T09:04:00Z',
          name: 'process inventory',
          action: 'added',
          columns: '{"pid":"1","name":"launchd"}',
        },
      ],
      type: 'result',
      uuid: 'abc12345-0000-0000-0000-000000000001',
      env: 'test-env',
      limit: 100,
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: 'Result logs' }));

    await waitFor(() => {
      expect(screen.getByText('process inventory')).toBeInTheDocument();
    });
    expect(screen.queryByText('osctrl:posture:firewall')).not.toBeInTheDocument();
  });

  it('shows posture uptime in lifecycle details only when posture is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetNode.mockResolvedValue(
      makeNode({
        uptime: {
          days: 7,
          hours: 3,
          minutes: 12,
          seconds: 9,
          total_seconds: 616329,
          last_seen: '2026-07-26T10:30:00Z',
        },
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.getByText('Uptime')).toBeInTheDocument();
    expect(screen.getByText('7d 3h 12m')).toBeInTheDocument();
  });

  it('shows node health and tags in the details view', async () => {
    mockGetNode.mockResolvedValue(
      makeNode({
        health: {
          status: 'attention',
          reason: 'Posture data unavailable',
          signals: ['active', 'posture unknown'],
        },
        tags: [
          {
            id: 1,
            created_at: '2026-07-26T10:00:00Z',
            updated_at: '2026-07-26T10:00:00Z',
            name: 'prod',
            description: 'Production',
            color: '#2ecc71',
            icon: 'tag',
            created_by: 'alice',
            custom_tag: 'tag',
            auto_tag: false,
            environment_id: 1,
            tag_type: 6,
            cohort: true,
          },
          {
            id: 2,
            created_at: '2026-07-26T10:00:00Z',
            updated_at: '2026-07-26T10:00:00Z',
            name: 'critical',
            description: 'Critical',
            color: '#e74c3c',
            icon: 'tag',
            created_by: 'alice',
            custom_tag: 'tag',
            auto_tag: false,
            environment_id: 1,
            tag_type: 6,
            cohort: true,
          },
        ],
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.getByText('Health')).toBeInTheDocument();
    expect(screen.getByText('Attention')).toBeInTheDocument();
    expect(screen.getByText('Posture data unavailable')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('posture unknown')).toBeInTheDocument();
    expect(screen.getByText('Tags')).toBeInTheDocument();
    expect(screen.getByText('prod')).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();
  });

  it('hides node uptime while posture is disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false });
    mockGetNode.mockResolvedValue(
      makeNode({
        uptime: {
          days: 7,
          hours: 3,
          minutes: 12,
          seconds: 9,
          total_seconds: 616329,
          last_seen: '2026-07-26T10:30:00Z',
        },
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByText('Uptime')).not.toBeInTheDocument();
    expect(screen.queryByText('7d 3h 12m')).not.toBeInTheDocument();
  });

  it('shows the console action when console is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, console: true, file_explorer: false });
    const router = makeTestRouter();

    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.getByRole('link', { name: /console/i })).toBeInTheDocument();
  });

  it('hides the console action when console is disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: true, console: false, file_explorer: false });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('link', { name: /console/i })).not.toBeInTheDocument();
  });

  it('hides the console action from non-admin users even when console is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, console: true, file_explorer: false });
    mockGetMe.mockResolvedValue({
      admin: false,
      permissions: {
        'env-uuid-1': { user: true, query: true, carve: false, admin: false },
      },
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('link', { name: /console/i })).not.toBeInTheDocument();
  });

  it('shows the file explorer tab when file explorer is enabled without acceleration', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: true });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.getByRole('tab', { name: /file explorer/i })).toBeInTheDocument();
  });

  it('lets the file explorer details panel stick to the page scroll container', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: true, file_explorer: true });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: /file explorer/i }));

    const panel = screen.getByRole('tabpanel', { name: /file explorer/i });
    expect(panel).toHaveClass('overflow-visible');
    expect(panel).not.toHaveClass('overflow-auto');
  });

  it('hides the file explorer tab when file explorer is disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: true, file_explorer: false });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('tab', { name: /file explorer/i })).not.toBeInTheDocument();
  });

  it('shows the vulnerabilities tab when vulnerability monitoring is enabled', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, vulnerabilities: true });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('tab', { name: 'Vulnerabilities' }));
    expect(screen.getByTestId('vulnerabilities-panel')).toBeInTheDocument();
  });

  it('hides the vulnerabilities tab while the feature is disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });
    expect(screen.queryByRole('tab', { name: 'Vulnerabilities' })).not.toBeInTheDocument();
  });

  it('wraps single-node actions away from the hostname block', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: true, file_explorer: false });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    const toolbar = screen.getByLabelText('Node actions');
    expect(toolbar).toHaveClass('grid');
    expect(toolbar).toHaveClass('grid-cols-2');
    expect(toolbar).toHaveClass('xl:flex');
  });

  it('runs a saved query against the current node from a modal', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue({
      admin: false,
      permissions: {
        'env-uuid-1': { user: true, query: true, carve: false, admin: false },
      },
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /run query/i }));
    await user.selectOptions(screen.getByLabelText('Saved query'), 'process inventory');
    await user.click(screen.getByRole('button', { name: /run on node/i }));

    await waitFor(() => {
      expect(mockRunQuery).toHaveBeenCalledWith('test-env', {
        query: 'select * from processes;',
        uuid_list: ['abc12345-0000-0000-0000-000000000001'],
        exp_hours: 24,
      });
    });
  });

  it('runs an ad-hoc query against the current node from a modal', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue({
      admin: false,
      permissions: {
        'env-uuid-1': { user: true, query: true, carve: false, admin: false },
      },
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /run query/i }));
    await user.type(screen.getByLabelText('SQL query'), 'select * from os_version;');
    await user.click(screen.getByRole('button', { name: /run on node/i }));

    await waitFor(() => {
      expect(mockRunQuery).toHaveBeenCalledWith('test-env', {
        query: 'select * from os_version;',
        uuid_list: ['abc12345-0000-0000-0000-000000000001'],
        exp_hours: 24,
      });
    });
  });

  it('starts a file carve against the current node from a modal', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue({
      admin: false,
      permissions: {
        'env-uuid-1': { user: true, query: false, carve: true, admin: false },
      },
    });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /carve file/i }));
    await user.type(screen.getByLabelText('File path'), '/etc/hosts');
    await user.click(screen.getByRole('button', { name: /start carve/i }));

    await waitFor(() => {
      expect(mockRunCarve).toHaveBeenCalledWith('test-env', {
        path: '/etc/hosts',
        uuid_list: ['abc12345-0000-0000-0000-000000000001'],
      });
    });
  });

  it('tags the current node from a modal', async () => {
    const user = userEvent.setup();

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /^tag$/i }));
    const dialog = screen.getByRole('dialog', { name: /tag web-server-01/i });
    await user.selectOptions(within(dialog).getByLabelText('Tag'), 'prod');
    await user.click(within(dialog).getByRole('button', { name: /apply tag/i }));

    await waitFor(() => {
      expect(mockTagNode).toHaveBeenCalledWith('test-env', {
        uuid: 'abc12345-0000-0000-0000-000000000001',
        tag: 'prod',
        type: 6,
      });
    });
  });

  it('creates and applies a custom tag from the node modal', async () => {
    const user = userEvent.setup();
    mockListEnvTags.mockResolvedValue([]);

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /^tag$/i }));
    const dialog = screen.getByRole('dialog', { name: /tag web-server-01/i });
    await user.type(within(dialog).getByLabelText('Custom tag'), 'incident-response');
    await user.click(within(dialog).getByRole('button', { name: /apply tag/i }));

    await waitFor(() => {
      expect(mockTagNode).toHaveBeenCalledWith('test-env', {
        uuid: 'abc12345-0000-0000-0000-000000000001',
        tag: 'incident-response',
        type: 6,
      });
    });
  });

  it('hides the node Alert button while the alerts feature is disabled', async () => {
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Run query' })).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Create alert for this node' })).not.toBeInTheDocument();
  });

  it('shows the node Alert button and creates a node-scoped rule', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, alerts: true });
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());
    const bell = await screen.findByRole('button', { name: 'Create alert for this node' });
    await user.click(bell);

    // Modal opens prefilled for this node.
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Node goes inactive/ })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Create alert' }));

    await waitFor(() => {
      expect(mockCreateAlertRule).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'web-server-01-inactive',
          source: 'node_inactive',
          node_uuid: 'abc12345-0000-0000-0000-000000000001',
          enabled: true,
        }),
      );
    });

    // Created confirmation offers the hot-reload apply.
    await user.click(await screen.findByRole('button', { name: 'Apply changes' }));
    await waitFor(() => expect(mockApplyAlerts).toHaveBeenCalled());
  });

  it('marks the node when a rule covers it, whichever scope it comes from', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, alerts: true });
    mockListAlertRules.mockResolvedValue([
      // env 5 is this page's environment (test-env); env 0 is global.
      { id: 1, name: 'node-errors', environment_id: 5, node_uuid: 'abc12345-0000-0000-0000-000000000001', enabled: true, source: 'status_log', match_type: 'substring', match_field: '', match_value: '', status_severity: 'error', cooldown_minutes: 0, channel_ids: [], created_at: '', updated_at: '', info: '' },
      { id: 2, name: 'env-wide', environment_id: 5, node_uuid: '', enabled: true, source: 'result_log', match_type: 'substring', match_field: '', match_value: 'x', status_severity: 'any', cooldown_minutes: 0, channel_ids: [], created_at: '', updated_at: '', info: '' },
      { id: 3, name: 'everywhere', environment_id: 0, node_uuid: '', enabled: true, source: 'result_log', match_type: 'substring', match_field: '', match_value: 'y', status_severity: 'any', cooldown_minutes: 0, channel_ids: [], created_at: '', updated_at: '', info: '' },
      // Neither of these reaches this node.
      { id: 4, name: 'other-node', environment_id: 5, node_uuid: 'SOMEONE-ELSE', enabled: true, source: 'result_log', match_type: 'substring', match_field: '', match_value: 'z', status_severity: 'any', cooldown_minutes: 0, channel_ids: [], created_at: '', updated_at: '', info: '' },
      { id: 5, name: 'switched-off', environment_id: 5, node_uuid: '', enabled: false, source: 'result_log', match_type: 'substring', match_field: '', match_value: 'w', status_severity: 'any', cooldown_minutes: 0, channel_ids: [], created_at: '', updated_at: '', info: '' },
    ]);

    renderWithProviders(makeTestRouter());

    const marker = await screen.findByLabelText('3 alert rules cover this node');
    expect(marker).toHaveTextContent('1 this node · 1 env · 1 global');
    // The tooltip names each rule and why it applies.
    expect(marker).toHaveAttribute('title', expect.stringContaining('node-errors — this node'));
    expect(marker).toHaveAttribute('title', expect.stringContaining('everywhere — global'));
    expect(marker).not.toHaveAttribute('title', expect.stringContaining('other-node'));
  });

  it('shows no alert marker when nothing covers the node', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, alerts: true });
    renderWithProviders(makeTestRouter());
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });
    expect(screen.queryByText(/alert rules? cover this node/)).not.toBeInTheDocument();
  });

  it('creates an error-severity rule on this node from the modal', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, alerts: true });
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());
    await user.click(await screen.findByRole('button', { name: 'Create alert for this node' }));

    await user.click(screen.getByRole('radio', { name: /Errors reported by this node/ }));
    // Predefined: no pattern for the operator to fill in.
    expect(screen.queryByLabelText(/Pattern/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create alert' }));

    await waitFor(() => {
      expect(mockCreateAlertRule).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'web-server-01-errors',
          source: 'status_log',
          status_severity: 'error',
          node_uuid: 'abc12345-0000-0000-0000-000000000001',
          match_value: '',
          enabled: true,
        }),
      );
    });
  });

  it('creates a log-match rule on this node from the modal', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false, alerts: true });
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());
    await user.click(await screen.findByRole('button', { name: 'Create alert for this node' }));

    await user.click(screen.getByRole('radio', { name: /Log match on this node/ }));
    await user.type(screen.getByLabelText(/Pattern.*/), '/etc/sudoers');
    await user.click(screen.getByRole('button', { name: 'Create alert' }));

    await waitFor(() => {
      expect(mockCreateAlertRule).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'result_log',
          node_uuid: 'abc12345-0000-0000-0000-000000000001',
          match_value: '/etc/sudoers',
        }),
      );
    });
  });
  it('shows the override banner and tab dot when an override exists', async () => {
    mockGetNodeConfig.mockResolvedValue(
      makeNodeConfig({
        override: '{"options":{}}',
        updated_by: 'alice',
        updated_at: '2026-10-01T10:00:00Z',
        expires_at: '2099-01-02T10:00:00Z',
      }),
    );
    renderWithProviders(makeTestRouter());
    expect(
      await screen.findByText(
        'This node has a configuration override, set by alice on 2026-10-01. It expires 2099-01-02.',
      ),
    ).toBeInTheDocument();
    expect(within(screen.getByRole('tab', { name: /Configuration/ })).getByTestId('config-override-dot')).toBeInTheDocument();
  });

  it('shows expired wording when the override has expired', async () => {
    mockGetNodeConfig.mockResolvedValue(
      makeNodeConfig({
        override: '{"options":{}}',
        updated_by: 'alice',
        updated_at: '2026-10-01T10:00:00Z',
        expires_at: '2026-10-05T10:00:00Z',
        expired: true,
      }),
    );
    renderWithProviders(makeTestRouter());
    expect(
      await screen.findByText(
        'This node has a configuration override, set by alice on 2026-10-01. It expired on 2026-10-05 and is no longer applied.',
      ),
    ).toBeInTheDocument();
  });

  it('no banner without an override', async () => {
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(mockGetNodeConfig).toHaveBeenCalled());
    await screen.findByRole('heading', { name: 'web-server-01' });
    expect(screen.queryByText(/has a configuration override/)).not.toBeInTheDocument();
    expect(screen.queryByTestId('config-override-dot')).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Configuration' })).toBeInTheDocument();
  });

  it('does not fetch the override or show the Configuration tab for non-admins', async () => {
    mockGetMe.mockResolvedValue({
      admin: false,
      permissions: { 'env-uuid-1': { user: true, query: true, carve: false, admin: false } },
    });
    renderWithProviders(makeTestRouter());
    await screen.findByRole('heading', { name: 'web-server-01' });
    await waitFor(() => expect(mockListEnvironments).toHaveBeenCalled());
    expect(screen.queryByRole('tab', { name: /Configuration/ })).not.toBeInTheDocument();
    expect(mockGetNodeConfig).not.toHaveBeenCalled();
    expect(mockGetNodeFlags).not.toHaveBeenCalled();
    expect(mockGetNodeExtensions).not.toHaveBeenCalled();
  });

  it('shows the banner and tab dot for a flags-only override', async () => {
    mockGetNodeFlags.mockResolvedValue(
      makeNodeFlags({
        override: '--verbose=true',
        updated_by: 'bob',
        updated_at: '2026-10-02T10:00:00Z',
        expires_at: '2099-01-02T10:00:00Z',
      }),
    );
    renderWithProviders(makeTestRouter());
    expect(
      await screen.findByText('This node has a flags override, set by bob on 2026-10-02. It expires 2099-01-02.'),
    ).toBeInTheDocument();
    expect(screen.queryByText(/has a configuration override/)).not.toBeInTheDocument();
    expect(within(screen.getByRole('tab', { name: /Configuration/ })).getByTestId('config-override-dot')).toBeInTheDocument();
  });

  it('shows expired wording for an expired flags override', async () => {
    mockGetNodeFlags.mockResolvedValue(
      makeNodeFlags({
        override: '--verbose=true',
        updated_by: 'bob',
        updated_at: '2026-10-02T10:00:00Z',
        expires_at: '2026-10-05T10:00:00Z',
        expired: true,
      }),
    );
    renderWithProviders(makeTestRouter());
    expect(
      await screen.findByText(
        'This node has a flags override, set by bob on 2026-10-02. It expired on 2026-10-05 and is no longer applied.',
      ),
    ).toBeInTheDocument();
  });

  it('shows the osquery down banner on the default tab and not when running', async () => {
    mockGetNodeFlags.mockResolvedValue(
      makeNodeFlags({
        osctrld: {
          apply_result: 'applied',
          apply_error: '',
          apply_at: null,
          rejected_current: false,
          osquery_running: false,
          down_since: '2026-10-20T08:00:00Z',
          reported_at: '2026-10-20T08:05:00Z',
        },
      }),
    );
    renderWithProviders(makeTestRouter());
    expect(await screen.findByTestId('osquery-down-banner')).toHaveTextContent('osquery is down since');
    expect(screen.getAllByTestId('osquery-down-banner')).toHaveLength(1);
  });

  it('no osquery down banner without a down report', async () => {
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(mockGetNodeFlags).toHaveBeenCalled());
    await screen.findByRole('heading', { name: 'web-server-01' });
    expect(screen.queryByTestId('osquery-down-banner')).not.toBeInTheDocument();
  });

  it('no flags banner without a flags override', async () => {
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(mockGetNodeFlags).toHaveBeenCalled());
    await screen.findByRole('heading', { name: 'web-server-01' });
    expect(screen.queryByText(/has a flags override/)).not.toBeInTheDocument();
  });

  describe('command execution banner', () => {
    const allowed = 'Command execution is allowed on this host via cmd-ext, set by root on 2026-10-03.';

    it('says allowed only when the last status is ok', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({ assignments: [hostAssignment()], status: [extStatus('ok')] }),
      );
      renderWithProviders(makeTestRouter());
      expect(await screen.findByText(allowed)).toBeInTheDocument();
      expect(screen.queryByText(/is not running/)).not.toBeInTheDocument();
      expect(within(screen.getByRole('tab', { name: /Configuration/ })).getByTestId('config-override-dot')).toBeInTheDocument();
    });

    it('adds the expiry to the allowed wording', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({
          assignments: [hostAssignment({ expires_at: '2099-01-02T10:00:00Z' })],
          status: [extStatus('ok')],
        }),
      );
      renderWithProviders(makeTestRouter());
      expect(await screen.findByText(`${allowed} It expires 2099-01-02.`)).toBeInTheDocument();
    });

    it('uses the expired wording for an expired assignment whose status is still ok', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({
          assignments: [hostAssignment({ expires_at: '2026-10-05T10:00:00Z', expired: true })],
          status: [extStatus('ok')],
        }),
      );
      renderWithProviders(makeTestRouter());
      expect(
        await screen.findByText('Command execution via cmd-ext expired on 2026-10-05 and is no longer applied.'),
      ).toBeInTheDocument();
      expect(screen.queryByText(/is allowed on this host/)).not.toBeInTheDocument();
    });

    it('does not claim it runs when the ok status says extensions are disabled', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({
          assignments: [hostAssignment()],
          status: [extStatus('ok', { error: 'extensions are disabled by flags' })],
        }),
      );
      renderWithProviders(makeTestRouter());
      expect(
        await screen.findByText('Command execution was assigned to this host via cmd-ext but is not running.'),
      ).toBeInTheDocument();
      expect(screen.queryByText(/is allowed on this host/)).not.toBeInTheDocument();
    });

    it('warns when a removed extension is still on the host, error as plain text', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({ status: [extStatus('kept', { error: '<b>still here</b>', lingering: true })] }),
      );
      renderWithProviders(makeTestRouter());
      const banner = await screen.findByText(
        'Command execution via cmd-ext was removed, but osctrld could not remove it from this host: <b>still here</b>',
      );
      expect(banner).toHaveAttribute('role', 'alert');
      expect(banner.querySelector('b')).toBeNull();
      expect(within(screen.getByRole('tab', { name: /Configuration/ })).getByTestId('config-override-dot')).toBeInTheDocument();
    });

    it('shows the lingering warning, not the expired wording, for an expired assignment osctrld kept', async () => {
      mockGetNodeExtensions.mockResolvedValue(
        makeNodeExtensions({
          assignments: [hostAssignment({ expires_at: '2026-10-05T10:00:00Z', expired: true })],
          status: [extStatus('kept', { error: 'cannot move', lingering: true })],
        }),
      );
      renderWithProviders(makeTestRouter());
      expect(
        await screen.findByText('Command execution via cmd-ext was removed, but osctrld could not remove it from this host: cannot move'),
      ).toBeInTheDocument();
      expect(screen.queryByText(/expired on .* and is no longer applied/)).not.toBeInTheDocument();
    });

    it('does not warn about a stale ok reported after the removal', async () => {
      mockGetNodeExtensions.mockResolvedValue(makeNodeExtensions({ status: [extStatus('ok')] }));
      renderWithProviders(makeTestRouter());
      await waitFor(() => expect(mockGetNodeExtensions).toHaveBeenCalled());
      await screen.findByRole('heading', { name: 'web-server-01' });
      expect(screen.queryByText(/Command execution/)).not.toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it.each([
      ['rejected status', [extStatus('rejected')]],
      ['no status yet', []],
    ])('says it is not running with %s', async (_n, status) => {
      mockGetNodeExtensions.mockResolvedValue(makeNodeExtensions({ assignments: [hostAssignment()], status }));
      renderWithProviders(makeTestRouter());
      expect(
        await screen.findByText('Command execution was assigned to this host via cmd-ext but is not running.'),
      ).toBeInTheDocument();
      expect(screen.queryByText(/is allowed on this host/)).not.toBeInTheDocument();
    });

    it('shows no banner or dot without a host assignment', async () => {
      renderWithProviders(makeTestRouter());
      await waitFor(() => expect(mockGetNodeExtensions).toHaveBeenCalled());
      await screen.findByRole('heading', { name: 'web-server-01' });
      expect(screen.queryByText(/Command execution/)).not.toBeInTheDocument();
      expect(screen.queryByTestId('config-override-dot')).not.toBeInTheDocument();
    });
  });
});
