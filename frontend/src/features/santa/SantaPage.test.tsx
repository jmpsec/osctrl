import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type {
  SantaConfig, SantaEventsPage, SantaMachine, SantaRule, SantaRuleInput,
} from '$/api/santa';
import { ApiError } from '$/api/client';
import { SantaPage } from './SantaPage';

const mockRules = vi.fn<() => Promise<SantaRule[]>>();
const mockDelete = vi.fn<(env: string, id: number) => Promise<unknown>>();
const mockCreate = vi.fn<(env: string, body: SantaRuleInput) => Promise<unknown>>();
const mockUpdate = vi.fn<(env: string, id: number, body: SantaRuleInput) => Promise<unknown>>();
const mockEvents = vi.fn<() => Promise<SantaEventsPage>>();
const mockMachines = vi.fn<() => Promise<SantaMachine[]>>();
const mockConfig = vi.fn<() => Promise<SantaConfig>>();
const mockRotate = vi.fn<() => Promise<{ token: string }>>();
const mockPutConfig = vi.fn<(env: string, body: unknown) => Promise<SantaConfig>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    listSantaRules: () => mockRules(),
    deleteSantaRule: (env: string, id: number) => mockDelete(env, id),
    createSantaRule: (env: string, body: SantaRuleInput) => mockCreate(env, body),
    updateSantaRule: (env: string, id: number, body: SantaRuleInput) => mockUpdate(env, id, body),
    listSantaEvents: () => mockEvents(),
    listSantaMachines: () => mockMachines(),
    getSantaConfig: () => mockConfig(),
    rotateSantaToken: () => mockRotate(),
    putSantaConfig: (env: string, body: unknown) => mockPutConfig(env, body),
  };
});
vi.mock('$/api/environments', () => ({
  getEnvironment: () => Promise.resolve({ uuid: 'ENV-UUID', hostname: 'tls.example.com' }),
}));

const rule: SantaRule = {
  id: 7, created_at: '', created_by: 'admin', identifier: 'a'.repeat(64), rule_type: 'BINARY',
  policy: 'BLOCKLIST', cel_expr: '', custom_msg: '', custom_url: '', scope: 'env', scope_value: '',
};

const config: SantaConfig = {
  client_mode: 'MONITOR', batch_size: 0, enable_transitive_rules: false, removable_media: 'ALLOW',
  removable_media_flags: null, encrypted_removable_media: '', encrypted_removable_media_flags: null, token_set: true,
};

function renderPage() {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: '/_app', component: Outlet });
  const envRoute = createRoute({ getParentRoute: () => appRoute, path: 'env/$env', component: Outlet });
  const pageRoute = createRoute({ getParentRoute: () => envRoute, path: 'santa', component: SantaPage });
  const router = createRouter({
    routeTree: rootRoute.addChildren([appRoute.addChildren([envRoute.addChildren([pageRoute])])]),
    history: createMemoryHistory({ initialEntries: ['/_app/env/dev/santa'] }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return qc;
}

describe('SantaPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRules.mockResolvedValue([rule]);
    mockDelete.mockResolvedValue({});
    mockCreate.mockResolvedValue({});
    mockUpdate.mockResolvedValue({});
    mockEvents.mockResolvedValue({
      events: [{
        id: 1, file_sha256: 'b'.repeat(64), file_path: '/tmp/bad', file_name: 'bad', executing_user: 'bob',
        decision: 'BLOCK_BINARY', team_id: '', signing_id: '', cd_hash: '', bundle_id: '', machine_id: 'M1',
        executed_at: '2026-01-01T00:00:00Z',
      }],
      total: 1, page: 1,
    });
    mockMachines.mockResolvedValue([{
      machine_id: 'M1', serial_number: 'SER1', hostname: 'mac-01', os_version: '15', santa_version: '2025.1',
      primary_user: 'bob', client_mode: 'LOCKDOWN', rule_count: 3, last_sync_at: null,
    }]);
    mockConfig.mockResolvedValue(config);
    mockPutConfig.mockResolvedValue(config);
    mockRotate.mockResolvedValue({ token: 'SECRET-TOKEN-123' });
  });

  it('lists rules and deletes one after confirmation', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText(rule.identifier)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Delete/ }));
    expect(mockDelete).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: /^Delete/ }));
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('dev', 7));
    expect(confirmSpy.mock.calls[0][0]).toContain(rule.identifier);
    confirmSpy.mockRestore();
  });

  it('edits a rule in place', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /^Edit/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit rule' });
    expect(within(dialog).getByLabelText(/Identifier/)).toHaveValue(rule.identifier);
    expect(within(dialog).getByLabelText('Policy')).toHaveValue('BLOCKLIST');
    await user.selectOptions(within(dialog).getByLabelText('Policy'), 'ALLOWLIST');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockUpdate).toHaveBeenCalled());
    expect(mockCreate).not.toHaveBeenCalled();
    const [env, id, body] = mockUpdate.mock.calls[0];
    expect([env, id]).toEqual(['dev', 7]);
    expect(body).toEqual({
      identifier: rule.identifier, rule_type: 'BINARY', policy: 'ALLOWLIST', cel_expr: '',
      custom_msg: '', custom_url: '', scope: 'env', scope_value: '',
    });
  });

  it('shows a friendly message when the rule already exists', async () => {
    mockCreate.mockRejectedValue(new ApiError('dup', 409));
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Add rule' }));
    await user.type(screen.getByLabelText(/Identifier/), 'c'.repeat(64));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('already exists');
  });

  it('does not post stale scope_value or cel_expr', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Add rule' }));
    await user.type(screen.getByLabelText(/Identifier/), 'c'.repeat(64));
    await user.selectOptions(screen.getByLabelText('Scope'), 'tag');
    await user.type(screen.getByLabelText(/Scope value/), 'x');
    await user.selectOptions(screen.getByLabelText('Scope'), 'env');
    await user.selectOptions(screen.getByLabelText('Policy'), 'CEL');
    await user.type(screen.getByLabelText(/^CEL/), 'true');
    await user.selectOptions(screen.getByLabelText('Policy'), 'ALLOWLIST');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockCreate).toHaveBeenCalled());
    expect(mockCreate.mock.calls[0][1]).toMatchObject({ scope: 'env', scope_value: '', policy: 'ALLOWLIST', cel_expr: '' });
  });

  it('prefills the rule form from an event', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Events' }));
    await user.click(await screen.findByRole('button', { name: 'Allow' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText(/Identifier/)).toHaveValue('b'.repeat(64));
    expect(within(dialog).getByLabelText('Rule type')).toHaveValue('BINARY');
    expect(within(dialog).getByLabelText('Policy')).toHaveValue('ALLOWLIST');
    expect(within(dialog).getByLabelText('Scope')).toHaveValue('env');
  });

  it('shows machines', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Machines' }));
    expect(await screen.findByText('mac-01')).toBeInTheDocument();
    expect(screen.getByText('LOCKDOWN')).toBeInTheDocument();
    expect(screen.getByText('Never')).toBeInTheDocument();
  });

  it('shows the sync URL and header on settings', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    expect(await screen.findByText('https://tls.example.com/ENV-UUID/santa/sync/')).toBeInTheDocument();
    expect(screen.getByText('X-Osctrl-Santa-Token: <token>')).toBeInTheDocument();
  });

  it('saves a remount policy with flags and leaves encrypted media inheriting', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    await user.selectOptions(await screen.findByLabelText('Removable media'), 'REMOUNT');
    await user.click(screen.getByRole('checkbox', { name: 'rdonly' }));
    await user.click(screen.getByRole('checkbox', { name: 'noexec' }));
    expect(screen.getByLabelText('Encrypted removable media')).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({
      removable_media: 'REMOUNT', removable_media_flags: ['rdonly', 'noexec'],
      encrypted_removable_media: '', encrypted_removable_media_flags: [],
    })));
  });

  it('asks for confirmation before rotating and cancel does not call the API', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    await user.click(await screen.findByRole('button', { name: 'Rotate token' }));
    const dlg = await screen.findByRole('dialog');
    expect(within(dlg).getByText(/disconnected/)).toBeInTheDocument();
    expect(mockRotate).not.toHaveBeenCalled();
    await user.click(within(dlg).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockRotate).not.toHaveBeenCalled();
  });

  it('shows a rotated token once and drops it on close', async () => {
    const user = userEvent.setup();
    const qc = renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    await user.click(await screen.findByRole('button', { name: 'Rotate token' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Rotate token' }));
    expect(await screen.findByText('SECRET-TOKEN-123')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(JSON.stringify(qc.getQueryCache().getAll().map((q) => q.state.data))).not.toContain('SECRET-TOKEN-123');
    // ModalShell also has an X button named "Close"; the footer button is last.
    await user.click(within(screen.getByRole('dialog')).getAllByRole('button', { name: 'Close' }).at(-1)!);
    await waitFor(() => expect(screen.queryByText('SECRET-TOKEN-123')).not.toBeInTheDocument());
  });
});
