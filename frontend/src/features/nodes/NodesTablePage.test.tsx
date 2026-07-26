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
import type { SettingValue } from '$/api/settings';
import type { Features } from '$/api/features';

// ---------------------------------------------------------------------------
// Mock the nodes API module
// ---------------------------------------------------------------------------
const mockListNodes = vi.fn<() => Promise<NodesPagedResponse>>();
const mockListServiceSettings = vi.fn<() => Promise<SettingValue[]>>();
const mockGetFeatures = vi.fn<() => Promise<Features>>();

vi.mock('$/api/nodes', () => ({
  listNodes: (...args: unknown[]) => mockListNodes(...(args as [])),
}));

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
    mockListServiceSettings.mockResolvedValue([]);
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false });
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
    mockGetFeatures.mockResolvedValue({ posture: true, accelerated: false });
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
                icon: 'fas fa-tag',
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
                icon: 'fas fa-tag',
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
    mockGetFeatures.mockResolvedValue({ posture: false, accelerated: false });
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
