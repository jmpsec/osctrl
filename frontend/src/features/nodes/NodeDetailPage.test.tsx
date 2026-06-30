import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
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
import type { OsqueryNode } from '$/api/types';
import type { NodeActivityBucket } from '$/api/stats';

const mockGetNode = vi.fn<() => Promise<OsqueryNode>>();
const mockListNodeLogs = vi.fn<() => Promise<unknown>>();
const mockDeleteNode = vi.fn<() => Promise<{ message: string }>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();
const mockListEnvironments = vi.fn<() => Promise<Array<{ name: string; uuid: string }>>>();
const mockGetNodeActivity = vi.fn<() => Promise<NodeActivityBucket[]>>();

vi.mock('$/api/nodes', () => ({
  getNode: (...args: unknown[]) => mockGetNode(...(args as [])),
  listNodeLogs: (...args: unknown[]) => mockListNodeLogs(...(args as [])),
  deleteNode: (...args: unknown[]) => mockDeleteNode(...(args as [])),
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
  };
});

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
    },
    {
      bucket_start: '2026-06-17T10:15:00Z',
      status: 1,
      result: 2,
      query: 1,
      carve: 0,
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
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    mockListEnvironments.mockResolvedValue([{ name: 'test-env', uuid: 'env-uuid-1' }]);
    mockGetNodeActivity.mockResolvedValue(makeActivityBuckets());
  });

  it('shows node activity in the default details view and removes the separate activity tab', async () => {
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'web-server-01' })).toBeInTheDocument();
    });

    expect(screen.queryByRole('tab', { name: 'Activity' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Details' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('heading', { name: /Node activity/i })).toBeInTheDocument();

    await waitFor(() => {
      expect(mockGetNodeActivity).toHaveBeenCalledWith(
        'test-env',
        'abc12345-0000-0000-0000-000000000001',
        '1d',
      );
    });
  });
});
