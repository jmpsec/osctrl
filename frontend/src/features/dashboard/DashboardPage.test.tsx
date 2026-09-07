import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { DashboardPage } from './DashboardPage';
import userEvent from '@testing-library/user-event';
import type { NodeTileSeries, StatsResponse, ErrorNodeRow } from '$/api/stats';
import type {
  CarvesPagedResponse,
  DistributedQuery,
  QueriesPagedResponse,
} from '$/api/types';

// ---------------------------------------------------------------------------
// Mock the stats API module
// ---------------------------------------------------------------------------
const mockGetStats = vi.fn<() => Promise<StatsResponse>>();
const mockGetEnvActivityTiles = vi.fn<(env: string, days?: number) => Promise<NodeTileSeries>>();
const mockGetEnvErrorNodes = vi.fn<(env: string, days?: number) => Promise<ErrorNodeRow[]>>();
const mockListQueries = vi.fn<() => Promise<QueriesPagedResponse>>();
const mockListCarves = vi.fn<() => Promise<CarvesPagedResponse>>();

vi.mock('$/api/stats', async () => {
  const actual = await vi.importActual<typeof import('$/api/stats')>('$/api/stats');
  return {
    ...actual,
    getStats: () => mockGetStats(),
    // Other dashboard panels call these; tests don't assert on them, so
    // resolve to empty so the queries don't reject and trigger extra logs.
    getOsqueryVersionCounts: () => Promise.resolve([]),
    getEnvActivityTiles: (env: string, days?: number) => mockGetEnvActivityTiles(env, days),
    getEnvErrorNodes: (env: string, days?: number) => mockGetEnvErrorNodes(env, days),
  };
});

vi.mock('$/api/queries', () => ({
  listQueries: (...args: unknown[]) => mockListQueries(...(args as [])),
}));

vi.mock('$/api/carves', () => ({
  listCarves: (...args: unknown[]) => mockListCarves(...(args as [])),
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
function makeStatsResponse(overrides: Partial<StatsResponse> = {}): StatsResponse {
  return {
    total_nodes: 10,
    active_nodes: 7,
    inactive_nodes: 3,
    inactive_hours: 72,
    total_active_queries: 2,
    total_active_carves: 1,
    platform_counts: { linux: 6, darwin: 2, windows: 2, other: 0 },
    environments: [
      {
        uuid: 'env-uuid-1',
        name: 'prod',
        active: 5,
        inactive: 2,
        total: 7,
        active_queries: 1,
        active_carves: 0,
        platform_counts: { linux: 4, darwin: 2, windows: 1, other: 0 },
      },
      {
        uuid: 'env-uuid-2',
        name: 'staging',
        active: 2,
        inactive: 1,
        total: 3,
        active_queries: 1,
        active_carves: 1,
        platform_counts: { linux: 2, darwin: 0, windows: 1, other: 0 },
      },
    ],
    ...overrides,
  };
}

function makeTileSeries(overrides: Partial<NodeTileSeries> = {}): NodeTileSeries {
  const buckets = 24;
  const start = new Date(Date.now() - (buckets - 1) * 60 * 60 * 1000).toISOString();
  const zeros = () => Array.from({ length: buckets }, () => 0);
  return {
    start,
    bucket_seconds: 3600,
    enroll: zeros(),
    status_error: zeros(),
    config: [...zeros().slice(0, buckets - 1), 3],
    status: [...zeros().slice(0, buckets - 2), 1, 2],
    result: [...zeros().slice(0, buckets - 3), 2, 1, 1],
    query_read: [...zeros().slice(0, buckets - 1), 1],
    query_write: [...zeros().slice(0, buckets - 1), 1],
    total: [...zeros().slice(0, buckets - 3), 2, 2, 7],
    ...overrides,
  };
}

function makeWorkloadItem(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 1,
    created_at: new Date(Date.now() - 10 * 60_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'incident-network-connections',
    creator: 'admin',
    query: 'SELECT * FROM process_open_sockets;',
    expected: 12,
    executions: 9,
    errors: 0,
    active: true,
    hidden: false,
    protected: false,
    completed: false,
    deleted: false,
    expired: false,
    type: 'query',
    path: '',
    environment_id: 1,
    extra_data: '',
    expiration: '',
    target: 'all',
    ...overrides,
  };
}

function pagedWorkload(items: DistributedQuery[]) {
  return { items, page: 1, page_size: items.length, total_items: items.length, total_pages: 1 };
}

// ---------------------------------------------------------------------------
// Test harness: wrap DashboardPage in a minimal router + QueryClient
// ---------------------------------------------------------------------------
function makeTestRouter() {
  const rootRoute = createRootRoute({ component: Outlet });

  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });

  // Env layout route — DashboardPage is now mounted under env/$env
  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });

  const dashRoute = createRoute({
    getParentRoute: () => envRoute,
    path: '/',
    component: DashboardPage,
  });

  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <div data-testid="nodes-page">nodes</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([dashRoute, nodesRoute]),
    ]),
  ]);

  const history = createMemoryHistory({ initialEntries: ['/_app/env/prod'] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  let ui: ReturnType<typeof render>;
  act(() => {
    ui = render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  });
  return ui!;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    mockGetEnvErrorNodes.mockResolvedValue([]);
    mockListQueries.mockResolvedValue(pagedWorkload([]));
    mockListCarves.mockResolvedValue(pagedWorkload([]));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton cards while loading (no data yet)', async () => {
    // Never resolves during this test — simulates pending network request
    mockGetStats.mockReturnValue(new Promise(() => {}));
    renderWithProviders(makeTestRouter());
    // Let the router's async route match resolve inside act() so the
    // MatchesInner state update does not leak out as an unhandled act warning.
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    // While loading, env names are not in the DOM
    expect(screen.queryByText('prod')).not.toBeInTheDocument();
    expect(screen.queryByText('staging')).not.toBeInTheDocument();
  });

  it('fetches 2 days of activity tiles so the trailing 24h window spans the UTC day boundary', async () => {
    // The Redis tile blobs are aligned to UTC midnight. Fetching days=1
    // right after midnight yields a single hourly bucket and the activity
    // chart rendered nothing; the trailing 12h/24h windows need 2 days.
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(mockGetEnvActivityTiles).toHaveBeenCalled());
    for (const call of mockGetEnvActivityTiles.mock.calls) {
      expect(call[1]).toBe(2);
    }
  });

  it('renders the page header', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    );
    expect(screen.getByText(/prod · osquery activity within the last 24 hours/)).toBeInTheDocument();
  });

  it('renders KPI card labels from the stats response', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive ≥ 72h')).toBeInTheDocument();
    expect(screen.getByText('Active Queries')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Carves' })).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Operational workload' })).toBeInTheDocument();
    expect(screen.getByText('Executing')).toBeInTheDocument();
    expect(screen.getByText('In flight')).toBeInTheDocument();
  });

  it('uses the card whitespace for query progress and a recent carve shortcut', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockListQueries.mockResolvedValue(pagedWorkload([
      makeWorkloadItem(),
    ]));
    mockListCarves.mockResolvedValue(pagedWorkload([
      makeWorkloadItem({
        id: 2,
        name: 'collect-suspicious-binary',
        query: '/tmp/update-agent',
        path: '/tmp/update-agent',
        expected: 2,
        executions: 1,
        type: 'carve',
        carve_status: 'ACTIVE',
      }),
    ]));

    renderWithProviders(makeTestRouter());

    const workload = await screen.findByRole('group', { name: 'Operational workload' });
    expect(within(workload).getByText('Query in progress')).toBeInTheDocument();
    expect(within(workload).getByText('Latest carve')).toBeInTheDocument();
    expect(await within(workload).findByRole('meter', { name: 'Query progress, 75% complete' })).toBeInTheDocument();
    expect(await within(workload).findByRole('meter', { name: 'Carve progress, 50% complete' })).toBeInTheDocument();
    expect(within(workload).getByRole('link', { name: /incident-network-connections/i })).toBeInTheDocument();
    expect(within(workload).getByRole('link', { name: /collect-suspicious-binary/i })).toBeInTheDocument();
  });

  // The tile replaced a "Failed enrolls" counter that read the audit log.
  // It now sums ERROR-severity status logs from the activity rollup, which is
  // the only source that works whatever logger.type the deployment uses.
  it('sums the last 24h of status errors into the reported-errors tile', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(
      makeTileSeries({ status_error: [2, 0, 3] }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(await screen.findByText('5 in 24h — see nodes')).toBeInTheDocument();
    // The old tile must be gone, not merely relabeled.
    expect(screen.queryByText('Failed enrolls (24h)')).not.toBeInTheDocument();
  });

  it('reads all clear when no errors were reported', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(screen.getByText('all clear')).toBeInTheDocument();
  });

  it('opens the erroring-nodes drill-down from the tile', async () => {
    const user = userEvent.setup();
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries({ status_error: [4] }));
    mockGetEnvErrorNodes.mockResolvedValue([
      { uuid: 'NODE-1', hostname: 'web-01', errors: 3 },
      // A node deleted since it errored keeps its row, shown by UUID.
      { uuid: 'NODE-2', hostname: '', errors: 1 },
    ]);
    renderWithProviders(makeTestRouter());

    const tile = await screen.findByRole('button', { name: /nodes reporting errors/i });
    await user.click(tile);

    expect(await screen.findByText('web-01')).toBeInTheDocument();
    expect(screen.getByText('NODE-2')).toBeInTheDocument();
    expect(mockGetEnvErrorNodes).toHaveBeenCalled();
  });

  // A tile with nothing behind it must not look clickable.
  it('leaves the errors tile inert when there are no errors', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(
      screen.queryByRole('button', { name: /nodes reporting errors/i }),
    ).not.toBeInTheDocument();
  });

  it('shows an Errors row in endpoint health', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries({ status_error: [7] }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Errors')).toBeInTheDocument());
  });

  it('includes reported errors in the activity chart', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(
      makeTileSeries({ status_error: [0, 2, 0, 5] }),
    );
    renderWithProviders(makeTestRouter());

    const chart = await screen.findByRole(
      'img',
      { name: /Node activity by category/i },
      // ActivityLineChart is intentionally code-split. A busy CI worker can
      // take longer than Testing Library's one-second default to resolve the
      // lazy module even though the same import is effectively instant in a
      // local run.
      { timeout: 5_000 },
    );

    // BKLiT's responsive plot intentionally does not lay out in jsdom, so
    // verify the chart's accessible series contract through its legend.
    expect(chart).toHaveAccessibleName(/including reported errors/i);
    const errorColor = screen.getByLabelText('Change Reported errors color');
    expect(errorColor).toHaveValue('#ff4d4f');
  });

  it('uses the backend stats threshold for inactive labeling', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ inactive_hours: 168 }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive ≥ 168h')).toBeInTheDocument();
  });

  it('renders one tile per environment', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => { expect(screen.getAllByText('prod').length).toBeGreaterThanOrEqual(1); });
    expect(screen.getAllByText('staging').length).toBeGreaterThanOrEqual(1);
  });

  it('renders env tile links to /env/{uuid}/nodes', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getAllByText('prod').length).toBeGreaterThanOrEqual(1);
    });

    const links = screen.getAllByRole('link');
    const hrefs = links.map((l) => l.getAttribute('href')).filter(Boolean);
    expect(hrefs).toContain('/_app/env/env-uuid-1/nodes');
    expect(hrefs).toContain('/_app/env/env-uuid-2/nodes');
  });

  it('shows empty state when environments array is empty', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ environments: [] }));
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByText('No environments configured.')).toBeInTheDocument(),
    );
  });

  it('shows endpoint health instead of recent enrollments', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    );

    expect(screen.getByText('Endpoint health')).toBeInTheDocument();
    expect(await screen.findByText('Query read')).toBeInTheDocument();
    expect(screen.getByText('Query write')).toBeInTheDocument();
    expect(screen.queryByText('Recent enrollments')).not.toBeInTheDocument();
  });

  it('shows error state and retry button when the API call fails', async () => {
    mockGetStats.mockRejectedValue(new Error('network failure'));
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByText('Failed to load stats.')).toBeInTheDocument(),
    );
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  // Regression: when the backend returns inactive_hours: 0 (e.g. setting
  // missing from DB), the dashboard must fall back to the default 72h
  // label rather than showing "Inactive >= 0h".
  it('falls back to default inactive threshold when API returns 0', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ inactive_hours: 0 }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive \u2265 72h')).toBeInTheDocument();
    expect(screen.queryByText('Inactive \u2265 0h')).not.toBeInTheDocument();
  });
});
