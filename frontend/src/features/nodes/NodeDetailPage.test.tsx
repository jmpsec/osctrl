import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
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
import type { NodePosture, OsqueryNode } from '$/api/types';
import type { NodeActivityBucket, NodeTileSeries } from '$/api/stats';
import type { SettingValue } from '$/api/settings';
import type { Features } from '$/api/features';

const mockGetNode = vi.fn<() => Promise<OsqueryNode>>();
const mockListNodeLogs = vi.fn<() => Promise<unknown>>();
const mockDeleteNode = vi.fn<() => Promise<{ message: string }>>();
const mockGetNodePosture = vi.fn<() => Promise<NodePosture[]>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();
const mockListEnvironments = vi.fn<() => Promise<Array<{ name: string; uuid: string }>>>();
const mockGetNodeActivity = vi.fn<() => Promise<NodeActivityBucket[]>>();
const mockGetNodeActivityTiles = vi.fn<() => Promise<NodeTileSeries>>();
const mockListServiceSettings = vi.fn<() => Promise<SettingValue[]>>();
const mockGetFeatures = vi.fn<() => Promise<Features>>();

vi.mock('$/api/nodes', () => ({
  getNode: (...args: unknown[]) => mockGetNode(...(args as [])),
  listNodeLogs: (...args: unknown[]) => mockListNodeLogs(...(args as [])),
  deleteNode: (...args: unknown[]) => mockDeleteNode(...(args as [])),
  getNodePosture: (...args: unknown[]) => mockGetNodePosture(...(args as [])),
}));

vi.mock('$/api/users', () => ({
  getMe: (...args: unknown[]) => mockGetMe(...(args as [])),
}));

vi.mock('$/api/environments', () => ({
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

vi.mock('$/api/settings', () => ({
  listServiceSettings: (...args: unknown[]) => mockListServiceSettings(...(args as [])),
}));

vi.mock('$/api/features', () => ({
  getFeatures: (...args: unknown[]) => mockGetFeatures(...(args as [])),
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

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([nodesRoute, nodeDetailRoute, queryNewRoute]),
    ]),
  ]);

  const history = createMemoryHistory({ initialEntries: [initialPath] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
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
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    mockListEnvironments.mockResolvedValue([{ name: 'test-env', uuid: 'env-uuid-1' }]);
    mockGetNodeActivity.mockResolvedValue(makeActivityBuckets());
    mockGetNodeActivityTiles.mockResolvedValue({
      start: new Date(Date.now() - 23 * 3600_000).toISOString(),
      bucket_seconds: 3600,
      enroll: [],
      config: [],
      status: [],
      result: [],
      query_read: [],
      query_write: [],
      total: [],
    });
    mockListServiceSettings.mockResolvedValue([]);
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false });
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

  it('shows posture data for the selected node', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, accelerated: false });
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

  it('hides posture tab while the posture feature is disabled', async () => {
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('tab', { name: 'Posture' })).not.toBeInTheDocument();
    expect(mockGetNodePosture).not.toHaveBeenCalled();
  });

  it('shows the console action only when accelerated queries are enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: true });
    const router = makeTestRouter();

    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.getByRole('link', { name: /console/i })).toBeInTheDocument();
  });

  it('hides the console action when accelerated queries are disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('link', { name: /console/i })).not.toBeInTheDocument();
  });

  it('hides the console action from non-admin users even when accelerated queries are enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: true });
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
});
