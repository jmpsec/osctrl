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
import { z } from 'zod';
import { AuditPage } from './AuditPage';
import type { AuditLogsPagedResponse, AuditLogsQuery } from '$/api/audit';

const mockList = vi.fn<(q?: AuditLogsQuery) => Promise<AuditLogsPagedResponse>>();

vi.mock('$/api/audit', async () => {
  const actual = await vi.importActual<typeof import('$/api/audit')>('$/api/audit');
  return {
    ...actual,
    listAuditLogs: (q?: AuditLogsQuery) => mockList(q),
  };
});

// AuditPage queries /api/v1/users/me to decide whether to show the
// Username filter input (super-admins only). Tests run a super-admin
// to keep the existing happy-path assertions valid.
vi.mock('$/api/users', () => ({
  getMe: () =>
    Promise.resolve({
      username: 'admin',
      email: '',
      fullname: 'admin',
      admin: true,
      service: false,
      uuid: 'aaaa',
      token_expire: new Date(Date.now() + 86_400_000).toISOString(),
      last_access: new Date().toISOString(),
      permissions: {},
    }),
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
  AuthError: class AuthError extends Error {
    readonly status = 401;
    constructor() {
      super('Unauthorized');
    }
  },
  ApiError: class ApiError extends Error {
    constructor(msg: string, public status: number, public code?: string) {
      super(msg);
    }
  },
}));

// Re-declare the search schema locally so the test route exposes the same
// validateSearch contract as the real route (avoids importing the real
// route which would also pull in /_app and the AppShell tree).
const auditSearchSchema = z.object({
  service: z.string().optional(),
  username: z.string().optional(),
  type: z.number().int().min(1).max(10).optional(),
  env_uuid: z.string().optional(),
  since: z.string().optional(),
  until: z.string().optional(),
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().optional(),
});

// The AuditPage uses useSearch({ from: '/_app/audit' }), so the test must
// register the same route id.
function makeResp(items: AuditLogsPagedResponse['items'] = []): AuditLogsPagedResponse {
  return {
    items,
    page: 1,
    page_size: 50,
    total_items: items.length,
    total_pages: items.length === 0 ? 0 : 1,
  };
}

function makeTestRouter(initialPath = '/_app/audit') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const auditRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'audit',
    validateSearch: auditSearchSchema,
    component: AuditPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([auditRoute]),
    loginRoute,
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

describe('AuditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders audit rows', async () => {
    mockList.mockResolvedValue(
      makeResp([
        {
          id: 1,
          created_at: new Date().toISOString(),
          service: 'admin',
          username: 'alice',
          line: 'user alice logged in',
          log_type: 1,
          severity: 1,
          source_ip: '10.0.0.1',
          environment_id: 0,
        },
      ]),
    );

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('user alice logged in')).toBeInTheDocument();
    });
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
  });

  it('shows empty state when no entries match', async () => {
    mockList.mockResolvedValue(makeResp([]));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No entries match these filters.')).toBeInTheDocument();
    });
  });

  it('passes filter query params to the API', async () => {
    mockList.mockResolvedValue(makeResp([]));
    renderWithProviders(
      makeTestRouter('/_app/audit?service=admin&type=1&page=1'),
    );

    await waitFor(() => {
      expect(mockList).toHaveBeenCalled();
    });
    // Find the most recent call's first argument
    const calls = mockList.mock.calls;
    const lastArgs = calls[calls.length - 1]?.[0];
    expect(lastArgs).toBeDefined();
    expect(lastArgs?.service).toBe('admin');
    expect(lastArgs?.type).toBe(1);
  });

  it('Apply filters button writes the username draft into the URL', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue(makeResp([]));

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No entries match these filters.')).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/Username/i), 'alice');
    await user.click(screen.getByRole('button', { name: /apply filters/i }));

    await waitFor(() => {
      const lastArgs = mockList.mock.calls[mockList.mock.calls.length - 1]?.[0];
      expect(lastArgs?.username).toBe('alice');
    });
  });
});
