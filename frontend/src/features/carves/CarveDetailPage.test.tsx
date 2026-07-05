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
import { CarveDetailPage } from './CarveDetailPage';
import type { CarveDetail, CarveFile, DistributedQuery } from '$/api/types';

const mockGetCarve = vi.fn<() => Promise<CarveDetail>>();
const mockActOnCarve = vi.fn<() => Promise<{ message: string }>>();
const mockListNodes = vi.fn<() => Promise<{ items: Array<{ uuid: string; hostname: string; localname: string }> }>>();

vi.mock('$/api/carves', () => ({
  getCarve: (...args: unknown[]) => mockGetCarve(...(args as [])),
  actOnCarve: (...args: unknown[]) => mockActOnCarve(...(args as [])),
  getCarveArchiveUrl: () => '/download.carve',
}));

vi.mock('$/api/nodes', () => ({
  listNodes: (...args: unknown[]) => mockListNodes(...(args as [])),
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
}));

function makeQuery(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 99,
    created_at: new Date(Date.now() - 60_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'carve_abcdef',
    creator: 'analyst',
    query: "SELECT * FROM carves WHERE carve=1 AND path = '/etc/hosts';",
    expected: 2,
    executions: 1,
    errors: 0,
    active: true,
    hidden: false,
    protected: false,
    completed: false,
    deleted: false,
    expired: false,
    type: 'carve',
    path: '/etc/hosts',
    environment_id: 1,
    extra_data: '',
    expiration: '0001-01-01T00:00:00Z',
    target: '',
    targets: [{ type: 'environment', value: 'test-env' }],
    ...overrides,
  };
}

function makeCarveDetail(overrides: Partial<CarveDetail> = {}): CarveDetail {
  return {
    query: makeQuery(),
    files: [],
    ...overrides,
  };
}

function makeFile(overrides: Partial<CarveFile> = {}): CarveFile {
  return {
    carve_id: 'carve-id-1',
    session_id: 'session-1',
    uuid: 'node-1',
    path: '/etc/hosts',
    status: 'SCHEDULED',
    carve_size: 0,
    block_size: 4096,
    total_blocks: 8,
    completed_blocks: 0,
    archived: false,
    created_at: new Date().toISOString(),
    completed_at: '0001-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/env/test-env/carves/carve_abcdef') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: '/_app', component: Outlet });
  const envRoute = createRoute({ getParentRoute: () => appRoute, path: 'env/$env', component: Outlet });
  const listRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'carves',
    component: () => <div data-testid="carves-page">carves</div>,
  });
  const detailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'carves/$name',
    component: CarveDetailPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([listRoute, detailRoute])]),
    loginRoute,
  ]);
  return createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('CarveDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetCarve.mockResolvedValue(makeCarveDetail());
    mockListNodes.mockResolvedValue({ items: [] });
    mockActOnCarve.mockResolvedValue({ message: 'ok' });
  });

  it('shows a complete button for incomplete carves and triggers the action', async () => {
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());

    const button = await screen.findByRole('button', { name: 'Complete carve' });
    await user.click(button);

    await waitFor(() => {
      expect(mockActOnCarve).toHaveBeenCalledWith('test-env', 'carve_abcdef', 'complete');
    });
  });

  it('hides the complete button for completed carves', async () => {
    mockGetCarve.mockResolvedValue(makeCarveDetail({ query: makeQuery({ active: false, completed: true }) }));
    renderWithProviders(makeTestRouter());

    await screen.findByText('/etc/hosts');
    expect(screen.queryByRole('button', { name: 'Complete carve' })).not.toBeInTheDocument();
  });

  it('shows the recorded targets', async () => {
    renderWithProviders(makeTestRouter());

    await screen.findByText('/etc/hosts');
    expect(screen.getByText('Targets')).toBeInTheDocument();
    expect(screen.getByText('environment:')).toBeInTheDocument();
    expect(screen.getByText('test-env')).toBeInTheDocument();
  });

  it('shows carve summary, per-file block/size/path columns and expiration', async () => {
    mockGetCarve.mockResolvedValue(
      makeCarveDetail({
        query: makeQuery({ expiration: '0001-01-01T00:00:00Z' }),
        files: [
          makeFile({
            carve_size: 4096,
            block_size: 1024,
            total_blocks: 4,
            completed_blocks: 4,
            status: 'COMPLETED',
            archived: true,
          }),
          makeFile({
            carve_size: 8192,
            block_size: 1024,
            total_blocks: 8,
            completed_blocks: 3,
            uuid: 'node-2',
            path: '/etc/passwd',
            status: 'IN PROGRESS',
            archived: false,
            session_id: 'session-2',
          }),
        ],
      }),
    );
    renderWithProviders(makeTestRouter());

    // The carve loads — wait for the summary band (unique), not the path,
    // which now also appears in each file row.
    await screen.findByText('Total size');

    // Summary band: 2 files (1 archived), total 12 KB, 7/12 blocks.
    expect(screen.getByText('Files')).toBeInTheDocument();
    // 'Blocks' appears both as the summary label and the table column header.
    expect(screen.getAllByText('Blocks').length).toBeGreaterThanOrEqual(2);
    // 'never' shown for the no-expiration carve.
    expect(screen.getByText('Expires')).toBeInTheDocument();
    expect(screen.getByText('never')).toBeInTheDocument();
    // Per-file path + archived columns render; max block size is surfaced
    // in the summary band rather than a redundant per-row column.
    expect(screen.getByText('/etc/passwd')).toBeInTheDocument();
    expect(screen.getByText('Max block size')).toBeInTheDocument();
    expect(screen.getByText('Archived')).toBeInTheDocument();
  });

  it('renders a Refresh button that reloads the carve', async () => {
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());

    // The carve loads on mount.
    await screen.findByText('/etc/hosts');
    expect(mockGetCarve).toHaveBeenCalledTimes(1);

    // The Refresh button (mirrors the query detail page) re-fetches.
    const refresh = await screen.findByRole('button', { name: 'Refresh carved files' });
    await user.click(refresh);
    await waitFor(() => {
      expect(mockGetCarve).toHaveBeenCalledTimes(2);
    });
  });

  it('does not render a fake completion date for scheduled files', async () => {
    mockGetCarve.mockResolvedValue(makeCarveDetail({ files: [makeFile()] }));
    mockListNodes.mockResolvedValue({
      items: [{ uuid: 'node-1', hostname: 'node-1.example', localname: 'node-1.example' }],
    });
    renderWithProviders(makeTestRouter());

    await screen.findByText('node-1.example');
    expect(screen.queryByText('31 Dec')).not.toBeInTheDocument();
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });
});
