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
import { AlertsPage } from './AlertsPage';
import type { AlertRule, AlertChannel, AlertChannelTypeSpec } from '$/api/alerts';
import type { ServiceCommand } from '$/api/service-config';

const mockListRules = vi.fn<(opts?: { env?: number }) => Promise<AlertRule[]>>();
const mockCreateRule = vi.fn();
const mockUpdateRule = vi.fn();
const mockDeleteRule = vi.fn<(id: number) => Promise<void>>();
const mockListChannels = vi.fn<
  (opts?: { env?: number; reveal?: boolean }) => Promise<AlertChannel[]>
>();
const mockChannelTypes = vi.fn<() => Promise<AlertChannelTypeSpec[]>>();
const mockCreateChannel = vi.fn();
const mockUpdateChannel = vi.fn();
const mockDeleteChannel = vi.fn<(id: number) => Promise<void>>();
const mockHistory = vi.fn<(limit?: number) => Promise<unknown[]>>();
const mockApply = vi.fn();
const mockGetCommand = vi.fn<(commandID: string) => Promise<ServiceCommand>>();

vi.mock('$/api/alerts', () => ({
  listAlertRules: (opts?: { env?: number }) => mockListRules(opts),
  createAlertRule: (...args: unknown[]) => mockCreateRule(...args),
  updateAlertRule: (...args: unknown[]) => mockUpdateRule(...args),
  deleteAlertRule: (id: number) => mockDeleteRule(id),
  listAlertChannels: (opts?: { env?: number; reveal?: boolean }) => mockListChannels(opts),
  listAlertChannelTypes: () => mockChannelTypes(),
  createAlertChannel: (...args: unknown[]) => mockCreateChannel(...args),
  updateAlertChannel: (...args: unknown[]) => mockUpdateChannel(...args),
  deleteAlertChannel: (id: number) => mockDeleteChannel(id),
  listAlertHistory: (limit?: number) => mockHistory(limit),
  applyAlerts: () => mockApply(),
}));

const mockGetFeatures = vi.fn();
vi.mock('$/api/features', () => ({
  getFeatures: () => mockGetFeatures(),
}));

const mockListEnvs = vi.fn();
vi.mock('$/api/environments', () => ({
  listEnvironments: () => mockListEnvs(),
}));

vi.mock('$/api/service-config', () => ({
  getServiceCommand: (commandID: string) => mockGetCommand(commandID),
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

function makeRule(overrides: Partial<AlertRule> = {}): AlertRule {
  return {
    id: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    name: 'sudoers-write',
    environment_id: 0,
    source: 'result_log',
    node_uuid: '',
    match_type: 'substring',
    match_field: 'path',
    match_value: '/etc/sudoers',
    status_severity: 'any',
    cooldown_minutes: 30,
    channel_ids: [1],
    enabled: true,
    info: '',
    ...overrides,
  };
}

function makeChannel(overrides: Partial<AlertChannel> = {}): AlertChannel {
  return {
    id: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    name: 'soc-webhook',
    environment_id: 0,
    type: 'webhook',
    enabled: true,
    config: { url: 'https://hooks.example.com/x', secret: '***' },
    info: '',
    ...overrides,
  };
}

const webhookType: AlertChannelTypeSpec = {
  type: 'webhook',
  description: 'HTTP POST to a URL with the alert as JSON',
  has_secret: true,
  secret_fields: ['secret'],
  fields: [
    { name: 'url', label: 'URL', type: 'string', required: true, placeholder: 'https://example.com/hook' },
    { name: 'secret', label: 'HMAC secret', type: 'secret', required: false },
    { name: 'timeoutSeconds', label: 'Timeout (seconds)', type: 'integer', required: false, default: 10 },
    { name: 'insecureSkipVerify', label: 'Skip TLS verify', type: 'boolean', required: false, default: false },
  ],
};

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const pageRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: AlertsPage,
  });
  const history = createMemoryHistory({ initialEntries: ['/'] });
  const router = createRouter({
    routeTree: rootRoute.addChildren([pageRoute]),
    history,
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetFeatures.mockResolvedValue({
    posture: false,
    service_config: true,
    log_sinks: true,
    alerts: true,
    accelerated: false,
    file_explorer: false,
  });
  mockListEnvs.mockResolvedValue([{ id: 5, name: 'prod', uuid: 'p', environment_id: 5 }]);
  mockChannelTypes.mockResolvedValue([webhookType]);
  mockListRules.mockResolvedValue([]);
  mockListChannels.mockResolvedValue([]);
  mockHistory.mockResolvedValue([]);
});

describe('AlertsPage', () => {
  it('renders the empty rules state when there are no rules', async () => {
    renderPage();
    expect(await screen.findByText('No alert rules')).toBeInTheDocument();
    // The empty state can render before features resolve (query still
    // disabled); wait for the actual fetch to confirm the wiring.
    await waitFor(() => expect(mockListRules).toHaveBeenCalledWith({ env: 0 }));
  });

  it('shows the disabled shell when the alerts feature is off', async () => {
    mockGetFeatures.mockResolvedValue({
      posture: false,
      service_config: true,
      log_sinks: true,
      alerts: false,
      accelerated: false,
      file_explorer: false,
    });
    renderPage();
    expect(await screen.findByText('Alerting is disabled')).toBeInTheDocument();
    // Disabled deployments must not hit the alerts endpoints at all.
    expect(mockListRules).not.toHaveBeenCalled();
  });

  it('lists rules with source, pattern and channels', async () => {
    mockListRules.mockResolvedValue([
      makeRule(),
      makeRule({ id: 2, name: 'node-offline', source: 'node_inactive', match_value: '', channel_ids: [] }),
    ]);
    mockListChannels.mockResolvedValue([makeChannel()]);
    renderPage();
    expect(await screen.findByText('sudoers-write')).toBeInTheDocument();
    expect(screen.getByText('Result logs')).toBeInTheDocument();
    expect(screen.getByText('Node inactive')).toBeInTheDocument();
    expect(screen.getByText('soc-webhook')).toBeInTheDocument();
    // node-state rule shows an em dash instead of a pattern
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2);
  });

  it('switches to the channels tab and lists channels', async () => {
    const user = userEvent.setup();
    mockListChannels.mockResolvedValue([makeChannel()]);
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'channels' }));
    expect(await screen.findByText('soc-webhook')).toBeInTheDocument();
    expect(screen.getByText('HTTP POST to a URL with the alert as JSON')).toBeInTheDocument();
  });

  it('switches to the history tab and lists dispatched alerts', async () => {
    const user = userEvent.setup();
    mockHistory.mockResolvedValue([
      {
        id: 1,
        created_at: new Date().toISOString(),
        rule_id: 1,
        rule_name: 'sudoers-write',
        channel_id: 1,
        channel_name: 'soc-webhook',
        environment: 'prod',
        node_uuid: 'U-1',
        entity: 'U-1:file_events',
        detail: '/etc/sudoers',
      },
    ]);
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'history' }));
    expect(await screen.findByText('sudoers-write')).toBeInTheDocument();
    expect(screen.getByText('soc-webhook')).toBeInTheDocument();
    expect(mockHistory).toHaveBeenCalled();
  });

  it('creates a rule through the editor modal', async () => {
    const user = userEvent.setup();
    mockListChannels.mockResolvedValue([makeChannel()]);
    mockCreateRule.mockResolvedValue(makeRule());
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'New rule' }));

    await user.type(screen.getByLabelText('Name'), 'sudoers-write');
    await user.type(screen.getByLabelText('Pattern'), '/etc/sudoers');
    await user.click(screen.getByRole('button', { name: 'Create rule' }));

    await waitFor(() => {
      expect(mockCreateRule).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'sudoers-write',
          source: 'result_log',
          match_value: '/etc/sudoers',
          enabled: true,
        }),
      );
    });
  });

  it('requires a pattern for pattern sources and validates', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'New rule' }));
    await user.type(screen.getByLabelText('Name'), 'no-pattern');
    await user.click(screen.getByRole('button', { name: 'Create rule' }));
    expect(
      await screen.findByText('Match value is required for pattern sources'),
    ).toBeInTheDocument();
    expect(mockCreateRule).not.toHaveBeenCalled();
  });

  it('hides pattern inputs for node-state sources', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'New rule' }));
    await user.selectOptions(screen.getByLabelText('Source'), 'node_inactive');
    expect(screen.queryByLabelText('Pattern')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Match type')).not.toBeInTheDocument();
  });

  it('creates a channel with registry-driven defaults', async () => {
    const user = userEvent.setup();
    mockCreateChannel.mockResolvedValue(makeChannel());
    renderPage();
    await user.click(await screen.findByRole('tab', { name: 'channels' }));
    await user.click(await screen.findByRole('button', { name: 'New channel' }));

    await user.type(screen.getByLabelText('Name'), 'soc-webhook');
    // Registry defaults (timeoutSeconds=10) prefill the form.
    expect(screen.getByLabelText('Timeout (seconds)')).toHaveValue(10);
    await user.type(screen.getByLabelText('URL'), 'https://hooks.example.com/x');
    await user.click(screen.getByRole('button', { name: 'Create channel' }));

    await waitFor(() => {
      expect(mockCreateChannel).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'soc-webhook',
          type: 'webhook',
          config: expect.objectContaining({
            url: 'https://hooks.example.com/x',
            timeoutSeconds: 10,
          }),
        }),
      );
    });
  });

  it('deletes a rule from the table', async () => {
    const user = userEvent.setup();
    mockListRules.mockResolvedValue([makeRule()]);
    mockDeleteRule.mockResolvedValue(undefined);
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(mockDeleteRule).toHaveBeenCalledWith(1));
  });

  it('apply triggers the reload command', async () => {
    const user = userEvent.setup();
    mockApply.mockResolvedValue({
      message: 'Reload requested',
      command: {
        command_id: 'cmd-1',
        status: 'consumed',
        service: 'osctrl-tls',
        action: 'reload-alerts',
      },
    });
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Apply changes' }));
    await waitFor(() => expect(mockApply).toHaveBeenCalled());
  });
});
