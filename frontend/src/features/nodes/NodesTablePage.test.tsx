import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
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
import { NodesTablePage } from './NodesTablePage';
import { nodesSearchSchema } from '$/routes/_app/env/$env/nodes';
import type { NodesPagedResponse } from '$/api/types';
import type { SettingValue } from '$/api/settings';
import type { Features } from '$/api/features';
import type { NodeTileSeries, StatsResponse } from '$/api/stats';

// ---------------------------------------------------------------------------
// Mock the nodes API module
// ---------------------------------------------------------------------------
const mockListNodes = vi.fn<() => Promise<NodesPagedResponse>>();
const mockListServiceSettings = vi.fn<() => Promise<SettingValue[]>>();
const mockGetFeatures = vi.fn<() => Promise<Features>>();
const mockGetStats = vi.fn<() => Promise<StatsResponse>>();
const mockGetNodeActivityTilesBatch = vi.fn<() => Promise<Record<string, NodeTileSeries>>>();

vi.mock('$/api/nodes', () => ({
  listNodes: (...args: unknown[]) => mockListNodes(...(args as [])),
}));

vi.mock('$/api/settings', () => ({
  listServiceSettings: (...args: unknown[]) => mockListServiceSettings(...(args as [])),
}));

vi.mock('$/api/features', () => ({
  getFeatures: (...args: unknown[]) => mockGetFeatures(...(args as [])),
}));

vi.mock('$/api/stats', () => ({
  getStats: (...args: unknown[]) => mockGetStats(...(args as [])),
  getNodeActivityTilesBatch: (...args: unknown[]) => mockGetNodeActivityTilesBatch(...(args as [])),
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

// ---------------------------------------------------------------------------
// Stub response factory
// ---------------------------------------------------------------------------
function makeResponse(overrides: Partial<NodesPagedResponse> = {}): NodesPagedResponse {
  return {
    items: [
      {
        id: 1,
        uuid: 'abc12345-0000-0000-0000-000000000001',
        hostname: 'web-server-01',
        localname: 'web01',
        ip_address: '10.0.0.1',
        platform: 'linux',
        platform_version: '22.04',
        osquery_version: '5.11.0',
        username: 'admin',
        osquery_user: 'root',
        environment: 'prod',
        cpu: 'Intel Xeon',
        memory: '8GB',
        hardware_serial: 'SN001',
        daemon_hash: 'abc',
        config_hash: 'def',
        bytes_received: 1024,
        last_seen: new Date(Date.now() - 60_000).toISOString(),
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
        user_id: 1,
        environment_id: 1,
        extra_data: '',
      },
    ],
    page: 1,
    page_size: 50,
    total_items: 1,
    total_pages: 1,
    ...overrides,
  };
}

function makeStatsResponse(overrides: Partial<StatsResponse> = {}): StatsResponse {
  return {
    total_nodes: 1,
    active_nodes: 1,
    inactive_nodes: 0,
    inactive_hours: 72,
    total_active_queries: 0,
    total_active_carves: 0,
    platform_counts: {
      linux: 1,
      darwin: 0,
      windows: 0,
      other: 0,
    },
    environments: [
      {
        uuid: 'test-env',
        name: 'test-env',
        active: 1,
        inactive: 0,
        total: 1,
        active_queries: 0,
        active_carves: 0,
        platform_counts: {
          linux: 1,
          darwin: 0,
          windows: 0,
          other: 0,
        },
      },
    ],
    ...overrides,
  };
}

function makeTileSeries(overrides: Partial<NodeTileSeries> = {}): NodeTileSeries {
  return {
    start: '2026-07-31T00:00:00Z',
    bucket_seconds: 3600,
    enroll: new Array(48).fill(0),
    config: new Array(48).fill(0),
    status: new Array(48).fill(0),
    result: new Array(48).fill(0),
    query_read: new Array(48).fill(0),
    query_write: new Array(48).fill(0),
    total: new Array(48).fill(0),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Router factory — paths mirror the production app structure exactly.
// The `from` string in useParams/useSearch is derived from the full route
// ID chain which is: rootRoute → /_app → env/$env → nodes.
// ---------------------------------------------------------------------------
function makeTestRouter(initialPath = '/_app/env/test-env/nodes') {
  const rootRoute = createRootRoute({ component: Outlet });

  // Layout route: path = /_app (matches production)
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
    validateSearch: nodesSearchSchema,
    component: NodesTablePage,
  });

  const nodeDetailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes/$uuid',
    component: () => <div data-testid="node-detail">Node detail</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([nodesRoute, nodeDetailRoute]),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NodesTablePage', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockListServiceSettings.mockResolvedValue([]);
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false, file_explorer: false });
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetNodeActivityTilesBatch.mockResolvedValue({
      'ABC12345-0000-0000-0000-000000000001': makeTileSeries(),
    });
  });

  it('renders node rows after loading', async () => {
    mockListNodes.mockResolvedValue(makeResponse());
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    expect(screen.getByText('abc12345')).toBeInTheDocument();
    expect(screen.getByText('linux')).toBeInTheDocument();
  });

  it('loads two Redis day blobs for the 24h activity column', async () => {
    mockListNodes.mockResolvedValue(makeResponse());

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(mockGetNodeActivityTilesBatch).toHaveBeenCalled();
    });

    expect(mockGetNodeActivityTilesBatch).toHaveBeenCalledWith(
      'test-env',
      ['abc12345-0000-0000-0000-000000000001'],
      2,
    );
  });

  it('renders exactly the trailing 24 hourly buckets from two-day activity data', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(new Date('2026-07-31T10:30:00Z').getTime());

    const status = new Array(48).fill(0);
    const total = new Array(48).fill(0);
    status[11] = 2;
    status[34] = 3;
    total[11] = 2;
    total[34] = 3;
    mockListNodes.mockResolvedValue(makeResponse());
    mockGetNodeActivityTilesBatch.mockResolvedValue({
      'abc12345-0000-0000-0000-000000000001': makeTileSeries({
        start: '2026-07-30T00:00:00Z',
        status,
        total,
      }),
    });

    renderWithProviders(makeTestRouter());

    const heatmap = await screen.findByRole('img', {
      name: /Node activity over the last 24 hours, 5 events total/i,
    });

    expect(heatmap.querySelectorAll('span')).toHaveLength(96);
  });

  it('shows nothing except skeleton rows while loading', async () => {
    // Never resolve
    mockListNodes.mockReturnValue(new Promise(() => {}));
    const router = makeTestRouter();
    renderWithProviders(router);
    // Let the router's async route match resolve inside act() so the
    // MatchesInner state update does not leak out as an unhandled act warning.
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    expect(screen.queryByText('web-server-01')).not.toBeInTheDocument();
  });

  it('shows empty state when API returns no items', async () => {
    mockListNodes.mockResolvedValue(
      makeResponse({ items: [], total_items: 0, total_pages: 0 }),
    );
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('No nodes match.')).toBeInTheDocument();
    });
  });

  it('clicking a sort header calls listNodes with the new sort', async () => {
    const user = userEvent.setup();
    mockListNodes.mockResolvedValue(makeResponse());
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    const hostnameButton = screen.getByRole('button', { name: /hostname/i });
    await user.click(hostnameButton);

    await waitFor(() => {
      const calls = mockListNodes.mock.calls as unknown as Array<[unknown]>;
      const lastArg = calls[calls.length - 1][0] as { sort?: string };
      expect(lastArg.sort).toBe('hostname');
    });
  });

  it('clicking a status tab calls listNodes with that status', async () => {
    const user = userEvent.setup();
    mockListNodes.mockResolvedValue(makeResponse());
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    // The status filter is now part of QuickFiltersGroup (chip pad)
    // which exposes itself via aria-label="Filter: Active" rather than
    // the bare button text 'active' that the old inline status pad used.
    const activeTab = screen.getByRole('button', { name: /^filter: active/i });
    await user.click(activeTab);

    await waitFor(() => {
      const calls = mockListNodes.mock.calls as unknown as Array<[unknown]>;
      const lastArg = calls[calls.length - 1][0] as { status?: string };
      expect(lastArg.status).toBe('active');
    });
  });

  it('hostname cell is a link to the node detail page', async () => {
    mockListNodes.mockResolvedValue(makeResponse());
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    const link = screen.getByRole('link', { name: 'web-server-01' });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute('href')).toContain('nodes');
  });

  it('shows a node as active when it was seen within the backend default 72 hour window', async () => {
    mockListNodes.mockResolvedValue(
      makeResponse({
        items: [
          {
            ...makeResponse().items[0],
            last_seen: new Date(Date.now() - 48 * 3600_000).toISOString(),
          },
        ],
      }),
    );
    const router = makeTestRouter();
    renderWithProviders(router);

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    expect(screen.getByText('active')).toBeInTheDocument();
  });

  it('shows uptime and posture risk badge when posture is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: true, accelerated: false, file_explorer: false });
    mockListNodes.mockResolvedValue(
      makeResponse({
        items: [
          {
            ...makeResponse().items[0],
            uptime: {
              days: 7,
              hours: 3,
              minutes: 12,
              seconds: 9,
              total_seconds: 616329,
              last_seen: '2026-07-26T10:30:00Z',
            },
            posture: {
              risk_level: 'high',
            },
          },
        ],
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    expect(screen.getByRole('columnheader', { name: 'Posture' })).toBeInTheDocument();
    expect(screen.getByText('Uptime 7d 3h')).toBeInTheDocument();
    const badge = screen.getByText('high');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute('aria-label', 'Posture risk high');
    expect(screen.queryByText('42')).not.toBeInTheDocument();

    const row = screen.getByText('web-server-01').closest('tr') as HTMLTableRowElement | null;
    expect(row).not.toBeNull();
    expect(row!.cells[6]).not.toHaveTextContent('Uptime');
    expect(row!.cells[6]).not.toHaveTextContent('Risk');
    expect(row!.cells[7]).toHaveTextContent('Uptime 7d 3h');
    expect(row!.cells[7]).toHaveTextContent('Risk');
  });

  it('shows health and tags in their own columns', async () => {
    mockListNodes.mockResolvedValue(
      makeResponse({
        items: [
          {
            ...makeResponse().items[0],
            health: {
              status: 'at_risk',
              reason: 'Posture risk high',
              signals: ['active', 'posture high'],
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
          },
        ],
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    expect(screen.getByRole('columnheader', { name: 'Health' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Tags' })).toBeInTheDocument();
    expect(screen.getByText('at risk')).toHaveAttribute('title', 'Posture risk high');
    expect(screen.getByText('prod')).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();

    const row = screen.getByText('web-server-01').closest('tr') as HTMLTableRowElement | null;
    expect(row).not.toBeNull();
    expect(row!.cells[2]).toHaveTextContent('at risk');
    expect(row!.cells[4]).toHaveTextContent('prod');
    expect(row!.cells[4]).toHaveTextContent('critical');
  });

  it('hides posture quick signals when posture is disabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false, file_explorer: false });
    mockListNodes.mockResolvedValue(
      makeResponse({
        items: [
          {
            ...makeResponse().items[0],
            uptime: {
              days: 7,
              hours: 3,
              minutes: 12,
              seconds: 9,
              total_seconds: 616329,
              last_seen: '2026-07-26T10:30:00Z',
            },
            posture: {
              risk_level: 'high',
            },
          },
        ],
      }),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('web-server-01')).toBeInTheDocument();
    });

    expect(screen.queryByRole('columnheader', { name: 'Posture' })).not.toBeInTheDocument();
    expect(screen.queryByText('Uptime 7d 3h')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Posture risk high')).not.toBeInTheDocument();
  });
});
