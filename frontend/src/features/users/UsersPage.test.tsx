import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
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
import { UsersPage } from './UsersPage';
import type { AdminTag, AdminUser, GetPermissionsResponse, UserMeResponse } from '$/api/types';
import type { TLSEnvironment } from '$/api/environments';
import { ApiError } from '$/api/client';

const mockGetMe = vi.fn<() => Promise<UserMeResponse>>();
const mockListUsers = vi.fn<() => Promise<AdminUser[]>>();
const mockGetPerms = vi.fn<() => Promise<GetPermissionsResponse>>();
const mockSetPerms = vi.fn();
const mockSetAll = vi.fn();
const mockEditRoles = vi.fn();
const mockCreate = vi.fn();
const mockListEnvs = vi.fn<() => Promise<TLSEnvironment[]>>();
const mockAllTags = vi.fn<() => Promise<AdminTag[]>>();

vi.mock('$/api/users', () => ({
  getMe: () => mockGetMe(),
  listUsers: () => mockListUsers(),
  getUserPermissions: () => mockGetPerms(),
  setUserPermissions: (...a: unknown[]) => mockSetPerms(...a),
  setUserPermissionsAllSafe: (...a: unknown[]) => mockSetAll(...a),
  editUserRoles: (...a: unknown[]) => mockEditRoles(...a),
  createUser: (...a: unknown[]) => mockCreate(...a),
  refreshUserToken: vi.fn(),
  deleteUserToken: vi.fn(),
  deleteUser: vi.fn(),
  adminResetUserPassword: vi.fn(),
}));

vi.mock('$/api/environments', () => ({ listEnvironments: () => mockListEnvs() }));

vi.mock('$/api/tags', () => ({
  listAllTags: () => mockAllTags(),
  listEnvTags: vi.fn(),
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

function makeMe(overrides: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'root', email: '', fullname: '', admin: false, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: 'aaaa',
    token_expire: new Date(Date.now() + 86_400_000).toISOString(),
    last_access: new Date().toISOString(), permissions: {}, preferred_language: '',
    ...overrides,
  };
}

let nextId = 1;
function makeUser(overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    id: nextId++, created_at: '', updated_at: '', username: 'bob', email: '', fullname: '',
    token_expire: '', admin: false, user_admin: false, env_manager: false, read_only_admin: false,
    alert_admin: false, service: false, uuid: '', last_ip_address: '', last_user_agent: '',
    last_access: new Date().toISOString(), last_token_use: '', environment_id: 0,
    ...overrides,
  };
}

function makeTag(overrides: Partial<AdminTag> = {}): AdminTag {
  return {
    id: 11, created_at: '', updated_at: '', name: 'prod-web', description: '', color: '#000',
    icon: '', created_by: '', custom_tag: '', auto_tag: false, environment_id: 3, tag_type: 0,
    cohort: false,
    ...overrides,
  };
}

const ENV = { id: 3, uuid: 'env-1', name: 'prod' } as TLSEnvironment;

function renderPage() {
  const rootRoute = createRootRoute({ component: Outlet });
  const usersRoute = createRoute({ getParentRoute: () => rootRoute, path: '/users', component: UsersPage });
  const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: '/login', component: () => <div>Login</div> });
  const router = createRouter({
    routeTree: rootRoute.addChildren([usersRoute, loginRoute]),
    history: createMemoryHistory({ initialEntries: ['/users'] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

async function row(username: string) {
  const cell = await screen.findByText(username);
  return cell.closest('tr')!;
}

async function openPermissions(username = 'bob') {
  const user = userEvent.setup();
  await user.click(within(await row(username)).getByRole('button', { name: /permissions/i }));
  const dialog = await screen.findByRole('dialog');
  await waitFor(() => expect(within(dialog).getByRole('option', { name: 'prod' })).toBeInTheDocument());
  return { user, dialog };
}

describe('UsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListUsers.mockResolvedValue([
      makeUser({ username: 'alice', admin: true }),
      makeUser({ username: 'bob' }),
    ]);
    mockGetMe.mockResolvedValue(makeMe({ admin: true }));
    mockListEnvs.mockResolvedValue([ENV]);
    mockGetPerms.mockResolvedValue({ username: 'bob', permissions: {} });
    mockAllTags.mockResolvedValue([
      makeTag(),
      makeTag({ id: 12, name: 'secret-hosts', sensitive: true }),
      makeTag({ id: 13, name: 'other-env-tag', environment_id: 9 }),
    ]);
    mockSetPerms.mockResolvedValue({});
    mockSetAll.mockResolvedValue({ total: 1, succeeded: 1, failed: [], usedBulkEndpoint: true });
    mockEditRoles.mockResolvedValue(undefined);
  });

  it('user admin: create modal offers roles but not Superuser; superuser rows have no actions', async () => {
    mockGetMe.mockResolvedValue(makeMe({ user_admin: true }));
    const user = userEvent.setup();
    renderPage();

    expect(within(await row('alice')).queryAllByRole('button')).toHaveLength(0);
    const bobRow = await row('bob');
    expect(within(bobRow).getByRole('button', { name: /roles/i })).toBeInTheDocument();
    expect(within(bobRow).getByRole('button', { name: /permissions/i })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add operator' }));
    const dialog = await screen.findByRole('dialog');
    for (const name of [/user management/i, /environment management/i, /read-only admin/i, /alert admin/i]) {
      expect(within(dialog).getByRole('checkbox', { name })).toBeInTheDocument();
    }
    expect(within(dialog).queryByRole('checkbox', { name: /superuser/i })).toBeNull();
  });

  it('read-only admin sees the list without write actions', async () => {
    mockGetMe.mockResolvedValue(makeMe({ read_only_admin: true }));
    renderPage();
    expect(within(await row('bob')).queryAllByRole('button')).toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Add operator' })).toBeNull();
    // bob is not a superuser, so the superuser label must not appear on his row.
    expect(within(await row('bob')).queryByLabelText(/superuser/i)).toBeNull();
    expect(within(await row('bob')).getByLabelText("You can't manage users")).toBeInTheDocument();
  });

  it('roles modal sends only changed fields', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(within(await row('bob')).getByRole('button', { name: /roles/i }));
    let dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('checkbox', { name: /environment management/i }));
    await user.click(within(dialog).getByRole('button', { name: /save roles/i }));
    await waitFor(() => expect(mockEditRoles).toHaveBeenCalledWith('bob', { env_manager: true }));

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await user.click(within(await row('alice')).getByRole('button', { name: /roles/i }));
    dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('checkbox', { name: /superuser/i }));
    await user.click(within(dialog).getByRole('button', { name: /save roles/i }));
    await waitFor(() => expect(mockEditRoles).toHaveBeenCalledWith('alice', { not_admin: true }));
  });

  it('roles modal shows server errors verbatim', async () => {
    mockEditRoles.mockRejectedValue(new ApiError('only a superuser can do that', 403));
    const user = userEvent.setup();
    renderPage();
    await user.click(within(await row('bob')).getByRole('button', { name: /roles/i }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('checkbox', { name: /alert admin/i }));
    await user.click(within(dialog).getByRole('button', { name: /save roles/i }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('only a superuser can do that');
  });

  it('permissions: tags tier with a picked tag and carve none are saved with tiers', async () => {
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    await user.selectOptions(within(dialog).getByLabelText('Query tier'), 'tags');
    const picker = await within(dialog).findByRole('group', { name: /scope tags/i });
    // Sensitive tags and other environments' tags are never offered.
    expect(within(picker).queryByText('secret-hosts')).toBeNull();
    expect(within(picker).queryByText('other-env-tag')).toBeNull();
    await user.click(within(picker).getByRole('checkbox', { name: 'prod-web' }));
    await user.selectOptions(within(dialog).getByLabelText('Carve tier'), 'none');
    await user.click(within(dialog).getByRole('button', { name: /save permissions/i }));

    await waitFor(() => expect(mockSetPerms).toHaveBeenCalled());
    const [username, body] = mockSetPerms.mock.calls[0]!;
    expect(username).toBe('bob');
    expect(body.env_uuid).toBe('env-1');
    expect(body.access).toMatchObject({
      query: true, query_tier: 'tags', scope_tags: [11], carve: false, carve_tier: 'none',
    });
  });

  it('permissions: loads tiers and disables them when Admin is checked', async () => {
    mockGetPerms.mockResolvedValue({
      username: 'bob',
      permissions: { 'env-1': { user: true, query: true, carve: true, admin: false, query_tier: 'full' } },
    });
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    const query = within(dialog).getByLabelText('Query tier');
    const carve = within(dialog).getByLabelText('Carve tier');
    await waitFor(() => expect(query).toHaveValue('full'));
    // No tier + boolean true reads as standard.
    expect(carve).toHaveValue('standard');

    await user.click(within(dialog).getByRole('checkbox', { name: /^admin/i }));
    expect(query).toBeDisabled();
    expect(carve).toBeDisabled();
    expect(query).toHaveDisplayValue('Full (environment admin)');
  });

  it('bulk save drops scope tags and offers no tags tier', async () => {
    mockGetPerms.mockResolvedValue({
      username: 'bob',
      permissions: {
        'env-1': { user: true, query: true, carve: false, admin: false, query_tier: 'standard', scope_tags: [7] },
      },
    });
    renderPage();
    const { user, dialog } = await openPermissions();
    const optionLabels = (el: HTMLElement) =>
      within(el).getAllByRole('option').map((o) => o.textContent);
    expect(optionLabels(within(dialog).getByLabelText('Query tier'))).toEqual(['None', 'Standard', 'Full']);
    expect(optionLabels(within(dialog).getByLabelText('Carve tier'))).toEqual(['None', 'Standard', 'Full']);

    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    await waitFor(() => expect(within(dialog).getByLabelText('Query tier')).toHaveValue('standard'));
    await user.click(within(dialog).getByRole('button', { name: /apply to all envs/i }));
    await user.click(within(dialog).getByRole('button', { name: /confirm: apply to all/i }));

    await waitFor(() => expect(mockSetAll).toHaveBeenCalled());
    const access = mockSetAll.mock.calls[0]![1];
    expect(access).not.toHaveProperty('scope_tags');
    expect(access).toMatchObject({ query: true, query_tier: 'standard', carve: false, carve_tier: 'none' });
  });

  it('bulk is disabled while a tier is Tags', async () => {
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    await user.selectOptions(within(dialog).getByLabelText('Carve tier'), 'tags');
    expect(within(dialog).getByRole('button', { name: /apply to all envs/i })).toBeDisabled();
    expect(within(dialog).getByText('Tag grants are per environment')).toBeInTheDocument();
  });

  it('single-env save drops scope tags the env no longer offers', async () => {
    mockGetPerms.mockResolvedValue({
      username: 'bob',
      permissions: {
        'env-1': { user: true, query: true, carve: false, admin: false, query_tier: 'tags', scope_tags: [11, 12, 13] },
      },
    });
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    expect(await within(dialog).findByRole('checkbox', { name: 'prod-web' })).toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: /save permissions/i }));
    await waitFor(() => expect(mockSetPerms).toHaveBeenCalled());
    expect(mockSetPerms.mock.calls[0]![1].access.scope_tags).toEqual([11]);
  });

  it('single-env save keeps scope tags when the tag list is unavailable', async () => {
    mockAllTags.mockRejectedValue(new Error('down'));
    mockGetPerms.mockResolvedValue({
      username: 'bob',
      permissions: {
        'env-1': { user: true, query: true, carve: false, admin: false, query_tier: 'tags', scope_tags: [11, 12, 13] },
      },
    });
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    await waitFor(() => expect(within(dialog).getByLabelText('Query tier')).toHaveValue('tags'));
    await waitFor(() => expect(mockAllTags).toHaveBeenCalled());
    await user.click(within(dialog).getByRole('button', { name: /save permissions/i }));
    await waitFor(() => expect(mockSetPerms).toHaveBeenCalled());
    expect(mockSetPerms.mock.calls[0]![1].access.scope_tags).toEqual([11, 12, 13]);
  });

  it('labels the empty select cell on superuser rows for a user admin', async () => {
    mockGetMe.mockResolvedValue(makeMe({ user_admin: true }));
    renderPage();
    const alice = await row('alice');
    expect(
      within(alice).getByLabelText('Superuser accounts can only be managed by a superuser'),
    ).toBeInTheDocument();
  });

  it('permissions: shows the server message on 400', async () => {
    mockSetPerms.mockRejectedValue(new ApiError('sensitive tag cannot be a scope tag', 400));
    renderPage();
    const { user, dialog } = await openPermissions();
    await user.selectOptions(within(dialog).getByLabelText('Environment'), 'env-1');
    await user.click(within(dialog).getByRole('button', { name: /save permissions/i }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('sensitive tag cannot be a scope tag');
  });

  it('list shows a badge for each role', async () => {
    mockListUsers.mockResolvedValue([
      makeUser({ username: 'alice', admin: true }),
      makeUser({ username: 'carol', user_admin: true, env_manager: true, read_only_admin: true, alert_admin: true }),
    ]);
    renderPage();
    expect(within(await row('alice')).getByText('Superuser')).toBeInTheDocument();
    const carol = await row('carol');
    for (const badge of ['User management', 'Environment management', 'Read-only admin', 'Alert admin']) {
      expect(within(carol).getByText(badge)).toBeInTheDocument();
    }
  });
});
