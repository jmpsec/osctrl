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
import type { AdminTag, UserMeResponse } from '$/api/types';

const mockList = vi.fn<() => Promise<AdminTag[]>>();
const mockAction = vi.fn();

vi.mock('$/api/tags', () => ({
  listEnvTags: () => mockList(),
  tagsAction: (...args: unknown[]) => mockAction(...args),
  tagNode: vi.fn(),
  listAllTags: vi.fn(),
  getEnvTag: vi.fn(),
}));

const mockGetMe = vi.fn<() => Promise<UserMeResponse>>();
const mockListEnvs = vi.fn();
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));
vi.mock('$/api/environments', () => ({ listEnvironments: () => mockListEnvs() }));

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

function makeMe(overrides: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'root', email: '', fullname: '', admin: true, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: 'aaaa',
    token_expire: new Date(Date.now() + 86_400_000).toISOString(),
    last_access: new Date().toISOString(), permissions: {}, preferred_language: '',
    ...overrides,
  };
}

function makeTag(overrides: Partial<AdminTag> = {}): AdminTag {
  return {
    id: 1,
    created_at: new Date(Date.now() - 600_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'production',
    description: 'Production environment',
    color: '#5b8def',
    icon: 'server',
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
    mockGetMe.mockResolvedValue(makeMe());
    mockListEnvs.mockResolvedValue([{ uuid: 'env-uuid', name: 'test-env' }]);
    mockAction.mockResolvedValue({ data: 'ok' });
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

  const CONFIRM =
    'Marking this tag sensitive removes it from every user\'s tag grants and cancels pending queries and carves that users below full tier can no longer reach.';

  async function openEdit(tag: AdminTag) {
    const user = userEvent.setup();
    mockList.mockResolvedValue([tag]);
    renderWithProviders(makeTestRouter());
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    await screen.findByRole('dialog');
    return user;
  }

  it('shows a Sensitive badge on sensitive tags only', async () => {
    mockList.mockResolvedValue([makeTag({ sensitive: true }), makeTag({ id: 2, name: 'staging' })]);
    renderWithProviders(makeTestRouter());
    await screen.findByText('staging');
    expect(screen.getAllByText('Sensitive')).toHaveLength(1);
  });

  it('sends sensitive: true when creating with Sensitive checked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());
    await user.click(await screen.findByRole('button', { name: /new tag/i }));
    await user.type(await screen.findByLabelText(/^name$/i), 'new_tag');
    await user.click(screen.getByLabelText('Sensitive'));
    await user.click(screen.getByRole('button', { name: /create tag/i }));
    await waitFor(() => expect(mockAction).toHaveBeenCalledTimes(1));
    expect(mockAction.mock.calls[0][2]).toMatchObject({ name: 'new_tag', sensitive: true });
  });

  it('confirms before marking an existing tag sensitive, then sends sensitive: true', async () => {
    const user = await openEdit(makeTag());
    await user.click(screen.getByLabelText('Sensitive'));
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    expect(await screen.findByText(CONFIRM)).toBeInTheDocument();
    expect(mockAction).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: /mark sensitive/i }));
    await waitFor(() => expect(mockAction).toHaveBeenCalledTimes(1));
    expect(mockAction.mock.calls[0][2]).toMatchObject({ sensitive: true });
  });

  it('shows a name conflict after confirming Mark sensitive', async () => {
    const { ApiError } = await import('$/api/client');
    mockAction.mockRejectedValue(new ApiError('conflict', 409));
    const user = await openEdit(makeTag());
    await user.click(screen.getByLabelText('Sensitive'));
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    await user.click(await screen.findByRole('button', { name: /mark sensitive/i }));
    expect(
      await screen.findByText('A tag with that name already exists in this environment.'),
    ).toBeInTheDocument();
  });

  it('sends nothing when the sensitive confirmation is cancelled', async () => {
    const user = await openEdit(makeTag());
    await user.click(screen.getByLabelText('Sensitive'));
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    await screen.findByText(CONFIRM);
    await user.click(screen.getByRole('button', { name: /^cancel$/i }));
    expect(mockAction).not.toHaveBeenCalled();
  });

  it('sends sensitive: false without confirmation when unchecking', async () => {
    const user = await openEdit(makeTag({ sensitive: true }));
    await user.click(screen.getByLabelText('Sensitive'));
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    await waitFor(() => expect(mockAction).toHaveBeenCalledTimes(1));
    expect(mockAction.mock.calls[0][2]).toMatchObject({ sensitive: false });
    expect(screen.queryByText(CONFIRM)).not.toBeInTheDocument();
  });

  it('omits sensitive on edit when the flag is unchanged', async () => {
    const user = await openEdit(makeTag({ sensitive: true }));
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    await waitFor(() => expect(mockAction).toHaveBeenCalledTimes(1));
    expect(mockAction.mock.calls[0][2]).not.toHaveProperty('sensitive');
  });

  it('hides write controls without env manage access', async () => {
    mockGetMe.mockResolvedValue(makeMe({ admin: false, read_only_admin: true }));
    mockList.mockResolvedValue([makeTag()]);
    renderWithProviders(makeTestRouter());
    await screen.findByText('production');
    expect(screen.queryByRole('button', { name: /new tag/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
