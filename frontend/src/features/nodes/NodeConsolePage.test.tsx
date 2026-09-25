import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeConsolePanel } from './NodeConsolePage';

const consoleApi = vi.hoisted(() => ({
  createConsoleSession: vi.fn(),
  closeConsoleSession: vi.fn(),
  getConsoleSession: vi.fn(),
  submitConsoleCommand: vi.fn(),
  getConsoleCommand: vi.fn(),
  getConsoleCommandResults: vi.fn(),
}));

const liveUpdates = vi.hoisted(() => ({
  readEvents: vi.fn(),
  getFeatures: vi.fn(),
}));

vi.mock('$/api/events', () => ({ readEvents: liveUpdates.readEvents }));
vi.mock('$/api/features', () => ({ getFeatures: liveUpdates.getFeatures }));

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}));

vi.mock('$/api/console', () => ({
  createConsoleSession: consoleApi.createConsoleSession,
  closeConsoleSession: consoleApi.closeConsoleSession,
  getConsoleSession: consoleApi.getConsoleSession,
  submitConsoleCommand: consoleApi.submitConsoleCommand,
  getConsoleCommand: consoleApi.getConsoleCommand,
  getConsoleCommandResults: consoleApi.getConsoleCommandResults,
}));

describe('NodeConsolePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    liveUpdates.getFeatures.mockResolvedValue({ events: true, event_topics: ['console'] });
    liveUpdates.readEvents.mockImplementation(() => new Promise<void>(() => undefined));
    consoleApi.createConsoleSession.mockResolvedValue({
      session: makeSession(),
      history: [],
    });
    consoleApi.closeConsoleSession.mockResolvedValue({ message: 'closed' });
    consoleApi.getConsoleSession.mockResolvedValue(makeSession());
    consoleApi.submitConsoleCommand.mockResolvedValue({
      command: makeCommand({ status: 'queued', input: 'ps' }),
      parsed: { kind: 'remote', command: 'ps' },
    });
    consoleApi.getConsoleCommand.mockResolvedValue(makeCommand({ status: 'queued', input: 'ps' }));
    consoleApi.getConsoleCommandResults.mockResolvedValue([{ pid: 1, name: 'launchd' }]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows spinner and disables input while command is pending', async () => {
    renderConsole();

    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    fireEvent.change(input, { target: { value: 'ps' } });
    fireEvent.submit(input.closest('form')!);

    expect(await screen.findByText(/waiting for node/i)).toBeInTheDocument();
    expect(input).toBeDisabled();
  });

  it('renders prior command history when the console opens', async () => {
    consoleApi.createConsoleSession.mockResolvedValue({
      session: makeSession(),
      history: [
        {
          command: makeCommand({ id: 7, status: 'completed', input: 'ps' }),
          results: [{ pid: 1, name: 'launchd' }],
        },
      ],
    });

    renderConsole();

    expect(await screen.findByText('ps')).toBeInTheDocument();
    expect(screen.getByText('launchd')).toBeInTheDocument();
  });

  it('focuses the command input when the console opens', async () => {
    renderConsole();

    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());
    expect(input).toHaveFocus();
  });

  it('refetches the priming command when a live update marks it changed', async () => {
    consoleApi.createConsoleSession.mockResolvedValue({
      session: makeSession(),
      history: [],
      priming: makeCommand({ id: 99, input: 'select version from osquery_info', priming: true }),
    });
    let receive: ((event: { event: string; data: Record<string, unknown> }) => void) | undefined;
    liveUpdates.readEvents.mockImplementation((_env: string, _topics: string[], _signal: AbortSignal, onEvent: typeof receive) => {
      receive = onEvent;
      return new Promise<void>(() => undefined);
    });
    let primingReads = 0;
    consoleApi.getConsoleCommand.mockImplementation((_env: string, _sessionID: number, commandID: number) => {
      if (commandID === 99) {
        primingReads += 1;
        return Promise.resolve(makeCommand({ id: 99, input: 'select version from osquery_info', priming: true, status: 'queued' }));
      }
      return Promise.resolve(makeCommand({ status: 'queued', input: 'ps' }));
    });

    renderConsole();
    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());
    // The session-scoped console stream must be connected before events
    // can drive the priming poll.
    await waitFor(() => expect(liveUpdates.readEvents).toHaveBeenCalled());
    const sessionScoped = liveUpdates.readEvents.mock.calls.some(([, topics, _signal, , options]) =>
      Array.isArray(topics) && topics.includes('console') && options?.consoleSessionId === 1,
    );
    expect(sessionScoped).toBe(true);
    const readsBefore = primingReads;
    act(() => {
      receive?.({ event: 'stream.ready', data: { environment_uuid: 'env-uuid' } });
      receive?.({
        event: 'resource.changed',
        data: { schema_version: 1, environment_uuid: 'env-uuid', topic: 'console', session_id: 1, resource_id: 99, change: 'results' },
      });
    });
    await waitFor(() => expect(primingReads).toBeGreaterThan(readsBefore));
  });

  it('keeps the console session fresh while open', async () => {
    const intervals: Array<() => void> = [];
    const originalSetInterval = window.setInterval.bind(window);
    const originalClearInterval = window.clearInterval.bind(window);
    const setIntervalSpy = vi.spyOn(window, 'setInterval').mockImplementation((handler, timeout, ...args) => {
      if (timeout === 10000 && typeof handler === 'function') {
        intervals.push(() => handler());
        return 1;
      }
      return originalSetInterval(handler as TimerHandler, timeout, ...args);
    });
    const clearIntervalSpy = vi.spyOn(window, 'clearInterval').mockImplementation((id) => {
      if (id === 1) return undefined;
      return originalClearInterval(id);
    });
    const rendered = renderConsole();

    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    expect(intervals).toHaveLength(1);
    intervals[0]();

    await waitFor(() => expect(consoleApi.getConsoleSession).toHaveBeenCalledWith('env', 1));
    rendered.unmount();
    expect(clearIntervalSpy).toHaveBeenCalledWith(1);
    setIntervalSpy.mockRestore();
    clearIntervalSpy.mockRestore();
  });

  it('keeps the command bar pinned outside the scrollback pane', async () => {
    consoleApi.createConsoleSession.mockResolvedValue({
      session: makeSession(),
      history: Array.from({ length: 30 }, (_, index) => ({
        command: makeCommand({ id: index + 1, status: 'completed', input: `ps ${index}` }),
        results: [{ pid: index + 1, name: `proc-${index}` }],
      })),
    });

    renderConsole();

    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());
    expect(screen.getByTestId('node-console-page')).toHaveClass('h-full');
    expect(input.closest('form')).toHaveAttribute('data-console-command-bar', 'true');
    expect(input.closest('form')).toHaveClass('sticky', 'bottom-0');
  });

  it('shows node connection and osquery metadata in the console header', async () => {
    consoleApi.createConsoleSession.mockResolvedValue({
      session: makeSession(),
      history: [],
      node_info: {
        ip_address: '10.0.0.8',
        osquery_user: 'root',
        osquery_version: '5.11.0',
        platform: 'darwin',
        platform_version: '14.5',
      },
    });

    renderConsole();

    expect(await screen.findByText('10.0.0.8')).toBeInTheDocument();
    expect(screen.getByText('root')).toBeInTheDocument();
    expect(screen.getByText('osquery')).toBeInTheDocument();
    expect(screen.getByText('5.11.0')).toBeInTheDocument();
    expect(screen.getByText('darwin 14.5')).toBeInTheDocument();
  });

  it('switches into and out of the osquery prompt', async () => {
    consoleApi.submitConsoleCommand.mockImplementation(async (_env, _sessionID, input) => {
      if (input === 'sql') {
        return { command: makeCommand({ input, status: 'completed' }), parsed: { kind: 'mode', command: 'sql', mode: 'osquery', message: 'entering osquery mode' } };
      }
      return { command: makeCommand({ input, status: 'completed' }), parsed: { kind: 'exit-mode', command: '.exit', mode: 'osquery', message: 'leaving osquery mode' } };
    });

    renderConsole();
    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    fireEvent.change(input, { target: { value: 'sql' } });
    fireEvent.submit(input.closest('form')!);

    await screen.findByText('entering osquery mode');
    expect(screen.getByText('osquery>')).toBeInTheDocument();

    fireEvent.change(input, { target: { value: '.exit' } });
    fireEvent.submit(input.closest('form')!);

    await screen.findByText('leaving osquery mode');
    expect(screen.queryByText('osquery>')).not.toBeInTheDocument();
  });

  it('sends osquery mode commands with the osquery_mode flag', async () => {
    consoleApi.submitConsoleCommand.mockResolvedValueOnce({
      command: makeCommand({ input: 'sql', status: 'completed' }),
      parsed: { kind: 'mode', command: 'sql', mode: 'osquery', message: 'entering osquery mode' },
    });

    renderConsole();
    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    fireEvent.change(input, { target: { value: 'sql' } });
    fireEvent.submit(input.closest('form')!);
    await screen.findByText('entering osquery mode');

    fireEvent.change(input, { target: { value: 'select * from osquery_info' } });
    fireEvent.submit(input.closest('form')!);

    await waitFor(() => {
      expect(consoleApi.submitConsoleCommand).toHaveBeenLastCalledWith('env', 1, 'select * from osquery_info', true);
    });
  });

  it('shows carve feedback for get without waiting for query results', async () => {
    consoleApi.submitConsoleCommand.mockResolvedValue({
      command: makeCommand({ input: 'get /etc/passwd', status: 'completed' }),
      parsed: { kind: 'carve', command: 'get', path: '/etc/passwd', message: 'created carve carve_abc' },
    });

    renderConsole();
    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    fireEvent.change(input, { target: { value: 'get /etc/passwd' } });
    fireEvent.submit(input.closest('form')!);

    await screen.findByText('created carve carve_abc');
    expect(screen.queryByText(/waiting for node/i)).not.toBeInTheDocument();
  });

  it('returns focus to the command input after Run is clicked', async () => {
    consoleApi.submitConsoleCommand.mockResolvedValue({
      command: makeCommand({ input: 'pwd', status: 'completed' }),
      parsed: { kind: 'local', command: 'pwd', output: '/' },
    });

    renderConsole();
    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());
    input.focus();

    fireEvent.change(input, { target: { value: 'pwd' } });
    const runButton = screen.getByRole('button', { name: 'Run' });
    runButton.focus();
    fireEvent.submit(input.closest('form')!);

    await screen.findByText('/');
    expect(input).toHaveFocus();
  });
});

function renderConsole() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <NodeConsolePanel env="env" uuid="NODE" />
    </QueryClientProvider>,
  );
}

function makeSession() {
  return {
    id: 1,
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
    environment_id: 1,
    node_id: 1,
    node_uuid: 'NODE',
    creator: 'alice',
    cwd: '/',
    platform: 'linux',
    active: true,
  };
}

function makeCommand(overrides: Record<string, unknown> = {}) {
  return {
    id: 10,
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
    session_id: 1,
    status: 'queued',
    input: 'ps',
    ...overrides,
  };
}
