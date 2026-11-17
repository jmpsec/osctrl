import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type {
  SantaConfig, SantaEventsPage, SantaImportResult, SantaMachine, SantaModeOverride, SantaRule, SantaRuleInput,
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
const mockImport = vi.fn<(env: string, rules: unknown[], dryRun: boolean) => Promise<SantaImportResult>>();
const mockModes = vi.fn<() => Promise<SantaModeOverride[]>>();
const mockSetMode = vi.fn<(env: string, body: unknown) => Promise<unknown>>();
const mockDeleteMode = vi.fn<(env: string, id: number) => Promise<unknown>>();
const mockFileAccess = vi.fn<() => Promise<unknown>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    listSantaRules: () => mockRules(),
    deleteSantaRule: (env: string, id: number) => mockDelete(env, id),
    createSantaRule: (env: string, body: SantaRuleInput) => mockCreate(env, body),
    updateSantaRule: (env: string, id: number, body: SantaRuleInput) => mockUpdate(env, id, body),
    importSantaRules: (env: string, rules: unknown[], dryRun: boolean) => mockImport(env, rules, dryRun),
    listSantaEvents: () => mockEvents(),
    listSantaMachines: () => mockMachines(),
    getSantaConfig: () => mockConfig(),
    rotateSantaToken: () => mockRotate(),
    putSantaConfig: (env: string, body: unknown) => mockPutConfig(env, body),
    listSantaModeOverrides: () => mockModes(),
    setSantaModeOverride: (env: string, body: unknown) => mockSetMode(env, body),
    deleteSantaModeOverride: (env: string, id: number) => mockDeleteMode(env, id),
    carveSantaEvent: (env: string, id: number) => mockCarve(env, id),
    listSantaFileAccessEvents: () => mockFileAccess(),
  };
});
const mockCarve = vi.fn<(env: string, id: number) => Promise<{ query_name: string }>>();
const mockGetCarve = vi.fn<(env: string, name: string) => Promise<unknown>>();
vi.mock('$/api/carves', () => ({ getCarve: (env: string, name: string) => mockGetCarve(env, name) }));
vi.mock('$/api/environments', () => ({
  getEnvironment: () => Promise.resolve({ id: 5, uuid: 'ENV-UUID', hostname: 'tls.example.com' }),
}));
const mockChannels = vi.fn<() => Promise<unknown[]>>();
vi.mock('$/api/alerts', () => ({ listAlertChannels: () => mockChannels() }));

const rule: SantaRule = {
  id: 7, created_at: '', created_by: 'admin', identifier: 'a'.repeat(64), rule_type: 'BINARY',
  policy: 'BLOCKLIST', cel_expr: '', custom_msg: '', custom_url: '', scope: 'env', scope_value: '',
};

const config: SantaConfig = {
  client_mode: 'MONITOR', batch_size: 0, enable_transitive_rules: false, removable_media: 'ALLOW',
  removable_media_flags: null, encrypted_removable_media: '', encrypted_removable_media_flags: null, approval_url: '', notify_channels: null,
  vote_local_threshold: 0, vote_global_threshold: 0, override_file_access_action: '', enable_bundles: false,
  enable_all_event_upload: false, disable_unknown_event_upload: false, allowed_path_regex: '', blocked_path_regex: '',
  event_detail_url: '', event_detail_text: '', token_set: true,
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
        executed_at: '2026-01-01T00:00:00Z', carve_name: '',
      }],
      total: 1, page: 1,
    });
    mockMachines.mockResolvedValue([{
      machine_id: 'M1', serial_number: 'SER1', hostname: 'mac-01', os_version: '15', santa_version: '2025.1',
      primary_user: 'bob', client_mode: 'MONITOR', assigned_mode: 'LOCKDOWN', mode_source: 'tag', rule_count: 3, last_sync_at: null,
    }]);
    mockModes.mockResolvedValue([{ id: 4, scope: 'tag', scope_value: 'pilot', client_mode: 'LOCKDOWN', created_by: 'admin', expires_at: null }]);
    mockSetMode.mockResolvedValue({});
    mockDeleteMode.mockResolvedValue({});
    mockConfig.mockResolvedValue(config);
    mockPutConfig.mockResolvedValue(config);
    // By default the caller has no alerts role: the channel list is refused.
    mockChannels.mockReset().mockRejectedValue(new Error('no access'));
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

  it('previews an import and applies it only when confirmed', async () => {
    const spec = { identifier: 'EQHXZ8M8AV', rule_type: 'TEAMID', policy: 'ALLOWLIST', scope: 'env' };
    mockImport.mockImplementation((_env, _rules, dryRun) =>
      Promise.resolve({ new: 1, duplicate: 2, conflicts: [], invalid: [], applied: !dryRun }));
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(rule.identifier);
    await user.upload(screen.getByLabelText('Import rules'), new File([JSON.stringify([spec])], 'rules.json', { type: 'application/json' }));
    const dialog = await screen.findByRole('dialog');
    expect(mockImport).toHaveBeenCalledWith('dev', [spec], true);
    expect(within(dialog).getByText('Already present (skipped)').nextSibling).toHaveTextContent('2');
    expect(mockImport).toHaveBeenCalledTimes(1);
    await user.click(within(dialog).getByRole('button', { name: 'Import 1 rules' }));
    await waitFor(() => expect(mockImport).toHaveBeenCalledWith('dev', [spec], false));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('blocks an import with conflicting rules and rejects a file that is not a rule list', async () => {
    mockImport.mockResolvedValue({
      new: 1, duplicate: 0, applied: false, invalid: [],
      conflicts: [{ index: 0, rule: { identifier: 'EQHXZ8M8AV', rule_type: 'TEAMID' }, reason: 'already has policy BLOCKLIST' }],
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(rule.identifier);
    const input = screen.getByLabelText('Import rules');
    await user.upload(input, new File(['{"not":"a list"}'], 'bad.json', { type: 'application/json' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('JSON list of rules');
    expect(mockImport).not.toHaveBeenCalled();

    await user.upload(input, new File(['[{}]'], 'rules.json', { type: 'application/json' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('already has policy BLOCKLIST')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Import 1 rules' })).toBeDisabled();
  });

  it('exports the rules as a JSON file without server fields', async () => {
    const blobs: Blob[] = [];
    const create = vi.fn((b: Blob) => { blobs.push(b); return 'blob:x'; });
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(rule.identifier);
    await user.click(screen.getByRole('button', { name: 'Export' }));
    expect(click).toHaveBeenCalled();
    const { id: _id, created_at: _at, created_by: _by, ...spec } = rule;
    expect(JSON.parse(await blobs[0].text())).toEqual([spec]);
    click.mockRestore();
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

  it('retrieves an event\'s file with a carve and shows its status', async () => {
    mockCarve.mockResolvedValue({ query_name: 'carve_abc' });
    mockGetCarve.mockResolvedValue({ query: { carve_status: 'ACTIVE' }, files: [] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Events' }));
    await user.click(await screen.findByRole('button', { name: 'Retrieve file' }));
    await waitFor(() => expect(mockCarve).toHaveBeenCalledWith('dev', 1));
    expect(await screen.findByRole('link', { name: 'View carve' })).toHaveAttribute('href', expect.stringContaining('carve_abc'));
    expect(await screen.findByText('Active')).toBeInTheDocument();
    expect(mockGetCarve).toHaveBeenCalledWith('dev', 'carve_abc');
  });

  it('shows the API error when the file cannot be retrieved', async () => {
    mockCarve.mockRejectedValue(new ApiError('the machine is not an osquery node of this environment', 409));
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Events' }));
    await user.click(await screen.findByRole('button', { name: 'Retrieve file' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('not an osquery node');
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

  it('offers the alert channels of this environment for request notifications', async () => {
    mockChannels.mockResolvedValue([
      { id: 3, name: 'soc-mail', type: 'email', environment_id: 0 },
      { id: 4, name: 'env-hook', type: 'webhook', environment_id: 5 },
      { id: 9, name: 'elsewhere', type: 'webhook', environment_id: 6 },
    ]);
    mockConfig.mockResolvedValue({ ...config, approval_url: 'https://osctrl.example.com', notify_channels: [3] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    expect(await screen.findByRole('checkbox', { name: /soc-mail/ })).toBeChecked();
    expect(screen.queryByRole('checkbox', { name: /elsewhere/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /env-hook/ }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({ notify_channels: [3, 4] })));
  });

  it('keeps the saved channels when the channel list is not available', async () => {
    mockConfig.mockResolvedValue({ ...config, approval_url: 'https://osctrl.example.com', notify_channels: [3] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    await screen.findByLabelText('Approval request URL');
    expect(screen.queryByText('Notify about new requests')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({ notify_channels: [3] })));
  });

  it('saves the vote thresholds', async () => {
    mockConfig.mockResolvedValue({ ...config, approval_url: 'https://osctrl.example.com', vote_local_threshold: 2 });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    expect(await screen.findByLabelText('Votes to allow on voters’ machines')).toHaveValue(2);
    const global = screen.getByLabelText('Votes to allow for the environment');
    await user.clear(global);
    await user.type(global, '5');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({ vote_local_threshold: 2, vote_global_threshold: 5 })));
  });

  it('saves the file access override', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    const select = await screen.findByLabelText('File access rules override');
    expect(select).toHaveValue('');
    await user.selectOptions(select, 'AUDIT_ONLY');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({ override_file_access_action: 'AUDIT_ONLY' })));
  });

  it('saves the v1 sync settings', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    await user.click(await screen.findByLabelText('Bundles: upload every binary of the bundle of a blocked app'));
    await user.click(screen.getByLabelText('Do not upload executions that LOCKDOWN would block'));
    await user.type(screen.getByLabelText('Blocked path regex'), '^/tmp/');
    await user.type(screen.getByLabelText('Block dialog URL'), 'https://wiki.example.com/');
    await user.type(screen.getByLabelText('Button label'), 'Help');
    const interval = screen.getByLabelText('Sync interval (seconds)');
    await user.clear(interval);
    await user.type(interval, '120');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(mockPutConfig).toHaveBeenCalledWith('dev', expect.objectContaining({
      full_sync_interval_seconds: 120, enable_bundles: true, enable_all_event_upload: false, disable_unknown_event_upload: true,
      allowed_path_regex: '', blocked_path_regex: '^/tmp/', event_detail_url: 'https://wiki.example.com/', event_detail_text: 'Help',
    })));
  });

  it('lists file access events with their process chain', async () => {
    mockFileAccess.mockResolvedValue({
      events: [{
        id: 3, machine_id: 'M1', rule_name: 'ChromeCookies', rule_version: 'v2', target: '/Users/bob/Cookies',
        decision: 'DENIED', accessed_at: '2026-01-01T00:00:00Z',
        process_chain: [{ pid: 42, file_path: '/tmp/evil', file_sha256: '', signing_id: '', team_id: '' },
          { pid: 1, file_path: '/sbin/launchd', file_sha256: '', signing_id: '', team_id: '' }],
      }],
      total: 1, page: 1,
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'File access' }));
    expect(await screen.findByText('ChromeCookies')).toBeInTheDocument();
    expect(screen.getByText('/Users/bob/Cookies')).toBeInTheDocument();
    expect(screen.getByText('/sbin/launchd')).toBeInTheDocument();
    expect(screen.getByText('DENIED')).toBeInTheDocument();
  });

  it('explains where file access events come from when there are none', async () => {
    mockFileAccess.mockResolvedValue({ events: [], total: 0, page: 1 });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'File access' }));
    expect(await screen.findByText('No file access events')).toBeInTheDocument();
  });

  it('adds and removes a mode override', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    expect(await screen.findByText('pilot')).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Scope'), 'node');
    await user.type(screen.getByLabelText(/Scope value/), '11111111-2222-3333-4444-555555555555');
    const duration = screen.getByLabelText('Duration');
    expect(duration).toBeDisabled();
    await user.selectOptions(screen.getAllByLabelText('Mode')[1], 'MONITOR');
    // Only MONITOR on a node can be temporary.
    expect(duration).toBeEnabled();
    await user.selectOptions(duration, '4');
    await user.click(screen.getByRole('button', { name: 'Add override' }));
    await waitFor(() => expect(mockSetMode).toHaveBeenCalledWith('dev', {
      scope: 'node', scope_value: '11111111-2222-3333-4444-555555555555', client_mode: 'MONITOR', hours: 4,
    }));
    await user.click(screen.getByRole('button', { name: 'Delete pilot' }));
    await waitFor(() => expect(mockDeleteMode).toHaveBeenCalledWith('dev', 4));
    confirmSpy.mockRestore();
  });

  it('shows when a temporary override ends', async () => {
    mockModes.mockResolvedValue([{
      id: 5, scope: 'node', scope_value: 'M1', client_mode: 'MONITOR', created_by: 'admin', expires_at: '2026-11-15T20:00:00Z',
    }]);
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Settings' }));
    expect(await screen.findByText(/^until /)).toBeInTheDocument();
  });

  it('shows the assigned mode and where it comes from', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'Machines' }));
    const row = (await screen.findByText('mac-01')).closest('tr')!;
    expect(within(row).getByText('LOCKDOWN')).toBeInTheDocument();
    expect(within(row).getByText('Tag override')).toBeInTheDocument();
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
