import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
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
import { LogSinksPage } from './LogSinksPage';
import type { LogSink, LogSinkTypeSpec } from '$/api/log-sinks';
import type { ServiceCommand } from '$/api/service-config';

const mockList = vi.fn<(opts?: { env?: number; reveal?: boolean }) => Promise<LogSink[]>>();
const mockTypes = vi.fn<() => Promise<LogSinkTypeSpec[]>>();
const mockCreate = vi.fn();
const mockUpdate = vi.fn();
const mockDelete = vi.fn();
const mockClone = vi.fn();
const mockApply = vi.fn();
const mockGetSink = vi.fn<(id: number, reveal?: boolean) => Promise<LogSink>>();
const mockGetCommand = vi.fn<(commandID: string) => Promise<ServiceCommand>>();

vi.mock('$/api/log-sinks', () => ({
  listLogSinks: (opts?: { env?: number; reveal?: boolean }) => mockList(opts),
  listLogSinkTypes: () => mockTypes(),
  createLogSink: (...args: unknown[]) => mockCreate(...args),
  updateLogSink: (...args: unknown[]) => mockUpdate(...args),
  deleteLogSink: (id: number) => mockDelete(id),
  cloneLogSinks: (...args: unknown[]) => mockClone(...args),
  applyLogSinks: () => mockApply(),
  getLogSink: (id: number, reveal?: boolean) => mockGetSink(id, reveal),
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

function makeSink(overrides: Partial<LogSink> = {}): LogSink {
  return {
    id: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    name: 'prod-splunk',
    environment_id: 0,
    type: 'splunk',
    enabled: true,
    order: 0,
    config: { url: 'http://x', token: '***', host: 'h', index: 'i' },
    source: 'yaml',
    info: '',
    ...overrides,
  };
}

const splunkType: LogSinkTypeSpec = {
  type: 'splunk',
  description: 'Splunk HEC',
  has_secret: true,
  secret_fields: ['token'],
  fields: [
    { name: 'url', label: 'HEC URL', type: 'string', required: true, secret: false, placeholder: 'https://splunk:8088/services/collector' },
    { name: 'token', label: 'HEC token', type: 'password', required: true, secret: true, placeholder: '' },
    { name: 'host', label: 'Host', type: 'string', required: false, secret: false, placeholder: 'osctrl' },
    { name: 'index', label: 'Index', type: 'string', required: false, secret: false, placeholder: 'main' },
  ],
};
const noneType: LogSinkTypeSpec = {
  type: 'none',
  description: 'Discard',
  has_secret: false,
};
const kafkaType: LogSinkTypeSpec = {
  type: 'kafka',
  description: 'Apache Kafka producer',
  has_secret: true,
  secret_fields: ['sasl.password'],
  fields: [
    { name: 'bootstrapServers', label: 'Bootstrap servers', type: 'string', required: true, secret: false, placeholder: 'broker1:9092' },
    { name: 'topic', label: 'Topic', type: 'string', required: true, secret: false, placeholder: 'osquery-logs' },
    { name: 'sslCALocation', label: 'CA cert path', type: 'string', required: false, secret: false, placeholder: '' },
    { name: 'connectionTimeout', label: 'Connection timeout', type: 'string', required: false, secret: false, placeholder: '5s' },
    { name: 'sasl.mechanism', label: 'SASL mechanism', type: 'select', required: false, secret: false, options: ['', 'SCRAM-SHA-256', 'SCRAM-SHA-512'] },
    { name: 'sasl.username', label: 'SASL username', type: 'string', required: false, secret: false, placeholder: '' },
    { name: 'sasl.password', label: 'SASL password', type: 'password', required: false, secret: true, placeholder: '' },
  ],
};

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const pageRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: LogSinksPage,
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
    accelerated: false,
    file_explorer: false,
  });
  mockListEnvs.mockResolvedValue([
    { id: 5, name: 'prod', uuid: 'p', environment_id: 5 },
  ]);
  mockTypes.mockResolvedValue([noneType, splunkType, kafkaType]);
  mockList.mockResolvedValue([]);
});

describe('LogSinksPage', () => {
  it('renders the env selector and empty state when there are no sinks', async () => {
    renderPage();
    await waitFor(() => expect(mockList).toHaveBeenCalled());
    expect(await screen.findByText('No global log sinks.')).toBeInTheDocument();
    expect(screen.getByText('Global (fallback for all)')).toBeInTheDocument();
  });

  it('lists existing sinks sorted by order', async () => {
    mockList.mockResolvedValue([
      makeSink({ id: 2, name: 'second', order: 5 }),
      makeSink({ id: 1, name: 'first', order: 0 }),
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText('first')).toBeInTheDocument());
    expect(screen.getByText('second')).toBeInTheDocument();
  });

  it('opens the type picker, picks splunk, and creates a sink with typed config', async () => {
    mockCreate.mockResolvedValue(makeSink({ id: 9, name: 'new' }));
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText('New sink')).toBeInTheDocument());
    await user.click(screen.getByText('New sink'));
    // Step 1: type picker modal.
    expect(await screen.findByText('New log sink')).toBeInTheDocument();
    expect(screen.getByText('splunk')).toBeInTheDocument();
    // Click the splunk type to advance to step 2.
    await user.click(screen.getByText('splunk'));
    // Step 2: config form for splunk.
    expect(await screen.findByText('Add splunk sink')).toBeInTheDocument();
    const urlInput = await screen.findByLabelText('HEC URL');
    expect(urlInput).toBeInTheDocument();
    expect(screen.getByLabelText('HEC token')).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('e.g. prod-splunk'), 'new');
    await user.type(urlInput, 'https://splunk:8088');
    await user.type(screen.getByLabelText('HEC token'), 'secret-token');
    await user.click(screen.getByText('Add sink'));
    await waitFor(() => expect(mockCreate).toHaveBeenCalled());
    const body = mockCreate.mock.calls[0][0];
    expect(body.name).toBe('new');
    expect(body.type).toBe('splunk');
    expect(body.config).toEqual({
      url: 'https://splunk:8088',
      token: 'secret-token',
    });
  });

  it('renders nested fields (kafka sasl) and submits a nested config object', async () => {
    mockCreate.mockResolvedValue(makeSink({ id: 10, name: 'kafka-sink' }));
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText('New sink')).toBeInTheDocument());
    await user.click(screen.getByText('New sink'));
    // Step 1: pick kafka from the type picker.
    expect(await screen.findByText('New log sink')).toBeInTheDocument();
    await user.click(screen.getByText('kafka'));
    // Step 2: SASL fields are nested under sasl.* in the schema; the
    // form should render them as flat labelled inputs and the submit
    // should expand them back into { sasl: { ... } }.
    expect(await screen.findByLabelText('Bootstrap servers')).toBeInTheDocument();
    expect(screen.getByLabelText('SASL mechanism')).toBeInTheDocument();
    expect(screen.getByLabelText('SASL password')).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('e.g. prod-splunk'), 'kafka-sink');
    await user.type(screen.getByLabelText('Bootstrap servers'), 'broker1:9092');
    await user.type(screen.getByLabelText('Topic'), 'osquery-logs');
    await user.selectOptions(screen.getByLabelText('SASL mechanism'), 'SCRAM-SHA-512');
    await user.type(screen.getByLabelText('SASL username'), 'kafka-user');
    await user.type(screen.getByLabelText('SASL password'), 'kafka-pass');
    await user.click(screen.getByText('Add sink'));
    await waitFor(() => expect(mockCreate).toHaveBeenCalled());
    const body = mockCreate.mock.calls[0][0];
    expect(body.type).toBe('kafka');
    expect(body.config).toEqual({
      bootstrapServers: 'broker1:9092',
      topic: 'osquery-logs',
      sasl: {
        mechanism: 'SCRAM-SHA-512',
        username: 'kafka-user',
        password: 'kafka-pass',
      },
    });
  });

  it('shows no config fields for the none sink type', async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText('New sink')).toBeInTheDocument());
    await user.click(screen.getByText('New sink'));
    // Step 1: pick none from the type picker.
    expect(await screen.findByText('New log sink')).toBeInTheDocument();
    await user.click(screen.getByText('none'));
    // Step 2: none has no fields — the empty-config hint renders.
    expect(await screen.findByText('This sink type has no configurable fields.')).toBeInTheDocument();
  });

  it('shows the apply warning modal and queues a reload on confirm', async () => {
    // The Apply button is disabled until there is at least one DB-edited
    // sink (source === 'db'), so seed one.
    mockList.mockResolvedValue([makeSink({ id: 1, name: 'edited', source: 'db' })]);
    mockApply.mockResolvedValue({
      message: 'ok',
      service: 'tls',
      command: {
        command_id: 'cmd-1',
        target_service: 'tls',
        action: 'reload-log-sinks',
        status: 'pending',
      },
    });
    mockGetCommand.mockResolvedValue({
      command_id: 'cmd-1',
      target_service: 'tls',
      action: 'reload-log-sinks',
      status: 'consumed',
    } as ServiceCommand);
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText('Apply changes')).toBeInTheDocument());
    await user.click(screen.getByText('Apply changes'));
    expect(await screen.findByText('Apply sink changes')).toBeInTheDocument();
    expect(
      screen.getByText(/logs in-flight to the old sinks may be dropped/),
    ).toBeInTheDocument();
    const confirmBtn = screen.getByText('Reload now');
    await user.click(confirmBtn);
    await waitFor(() => expect(mockApply).toHaveBeenCalled());
  });

  it('hides itself when the log_sinks feature flag is off', async () => {
    mockGetFeatures.mockResolvedValue({
      posture: false,
      service_config: false,
      log_sinks: false,
      accelerated: false,
      file_explorer: false,
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('Log Sinks API is disabled')).toBeInTheDocument(),
    );
    expect(mockList).not.toHaveBeenCalled();
  });
});
