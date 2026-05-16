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
import { NodesTablePage } from './NodesTablePage';
import { nodesSearchSchema } from '$/routes/_app/env/$env/nodes';
import type { NodesPagedResponse } from '$/api/types';

// ---------------------------------------------------------------------------
// Mock the nodes API module
// ---------------------------------------------------------------------------
const mockListNodes = vi.fn<() => Promise<NodesPagedResponse>>();

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
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NodesTablePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

  it('shows nothing except skeleton rows while loading', () => {
    // Never resolve
    mockListNodes.mockReturnValue(new Promise(() => {}));
    const router = makeTestRouter();
    renderWithProviders(router);
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

    const activeTab = screen.getByRole('button', { name: /^active$/i });
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
});
