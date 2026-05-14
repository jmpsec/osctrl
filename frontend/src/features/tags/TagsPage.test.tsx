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
import { TagsPage } from './TagsPage';
import type { AdminTag } from '$/api/types';

const mockList = vi.fn<() => Promise<AdminTag[]>>();
const mockAction = vi.fn();

vi.mock('$/api/tags', () => ({
  listEnvTags: () => mockList(),
  tagsAction: (...args: unknown[]) => mockAction(...args),
  tagNode: vi.fn(),
  listAllTags: vi.fn(),
  getEnvTag: vi.fn(),
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
    constructor(msg: string, public status: number, public code?: string) {
      super(msg);
    }
  },
}));

function makeTag(overrides: Partial<AdminTag> = {}): AdminTag {
  return {
    id: 1,
    created_at: new Date(Date.now() - 600_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'production',
    description: 'Production environment',
    color: '#5b8def',
    icon: 'fas fa-server',
    created_by: 'admin',
    custom_tag: 'tag',
    auto_tag: false,
    environment_id: 1,
    tag_type: 6,
    cohort: false,
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/env/test-env/tags') {
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
  const tagsRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'tags',
    component: TagsPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([tagsRoute])]),
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

describe('TagsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders tag rows after loading', async () => {
    mockList.mockResolvedValue([makeTag(), makeTag({ id: 2, name: 'staging' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('production')).toBeInTheDocument();
    });
    expect(screen.getByText('staging')).toBeInTheDocument();
  });

  it('shows the empty state CTA when no tags exist', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No tags in this environment yet.')).toBeInTheDocument();
    });
    expect(
      screen.getByRole('button', { name: /create your first tag/i }),
    ).toBeInTheDocument();
  });

  it('opens the create modal and calls tagsAction(add) on submit', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([]);
    mockAction.mockResolvedValue({ data: 'tag added successfully' });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No tags in this environment yet.')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /new tag/i }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();

    const nameInput = screen.getByLabelText(/^name$/i);
    await user.type(nameInput, 'new_tag');
    await user.click(screen.getByRole('button', { name: /create tag/i }));

    await waitFor(() => {
      expect(mockAction).toHaveBeenCalledTimes(1);
    });
    const args = mockAction.mock.calls[0] as [string, string, { name: string }];
    expect(args[0]).toBe('test-env');
    expect(args[1]).toBe('add');
    expect(args[2].name).toBe('new_tag');
  });
});
