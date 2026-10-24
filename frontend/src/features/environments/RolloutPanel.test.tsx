import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RolloutPanel } from './RolloutPanel';
import type { EnvOsquery, EnvOsqueryRollout } from '$/api/types';

const api = vi.hoisted(() => ({ resumeEnvRollout: vi.fn(), abortEnvRollout: vi.fn() }));
vi.mock('$/api/osqueryVersions', () => api);

const NOW = new Date('2026-10-23T12:00:00Z');

function make(o: Partial<EnvOsqueryRollout> = {}): EnvOsqueryRollout {
  return {
    state: 'running',
    request_id: 'r1',
    version: '5.14.0',
    stage: 2,
    stages: [1, 10, 50, 100],
    stage_opened_at: '2026-10-23T10:00:00Z',
    next_stage_at: '2026-10-23T13:20:00Z',
    counts: { eligible: 412, upgraded: 388, waiting: 24, rolled_back: 0 },
    paused: null,
    rolled_back_hosts: [],
    ...o,
  };
}

const paused = (o: Partial<EnvOsqueryRollout> = {}) =>
  make({
    state: 'paused',
    next_stage_at: null,
    counts: { eligible: 412, upgraded: 388, waiting: 23, rolled_back: 1 },
    paused: { host: 'web-prod-114', reason: 'version_not_reported', at: '2026-10-23T11:35:00Z' },
    rolled_back_hosts: [{ host: 'web-prod-114', reason: 'version_not_reported', at: '2026-10-23T11:35:00Z' }],
    ...o,
  });

let qc: QueryClient;
function renderPanel(r: EnvOsqueryRollout) {
  return render(
    <QueryClientProvider client={qc}>
      <RolloutPanel env="prod" rollout={r} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => vi.useRealTimers());

describe('RolloutPanel', () => {
  it('running: stage bar, counts, next stage and abort', () => {
    renderPanel(make());
    const steps = screen.getAllByRole('listitem').map((li) => li.textContent);
    expect(steps).toEqual(['1% · done', '10% · now', '50%', '100%']);
    expect(screen.getByText('eligible now').nextSibling).toHaveTextContent('412');
    expect(screen.getByText('upgraded').nextSibling).toHaveTextContent('388');
    expect(screen.getByText('waiting to sync').nextSibling).toHaveTextContent('24');
    expect(screen.getByText('rolled back').nextSibling).toHaveTextContent('0');
    expect(screen.getByText('Widens to 50% in about 1 h 20 min if nothing rolls back.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Abort rollout' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Resume rollout' })).toBeNull();
  });

  it('paused: banner, rolled back table in words, resume and abort', () => {
    renderPanel(paused());
    expect(screen.getByRole('status')).toHaveTextContent('Paused at 10%. 1 host rolled back, so the rollout stopped widening.');
    const row = screen.getByRole('row', { name: /web-prod-114/ });
    expect(row).toHaveTextContent(/never reported to osctrl/);
    expect(row).toHaveTextContent('25 min ago');
    expect(screen.getByRole('button', { name: 'Resume rollout' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Abort rollout' })).toBeInTheDocument();
  });

  it('completed and aborted are one line', () => {
    const { unmount } = renderPanel(make({ state: 'completed', stage: 4 }));
    expect(screen.getByText(/Rollout to 5\.14\.0 completed/)).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
    unmount();
    renderPanel(make({ state: 'aborted' }));
    expect(screen.getByText(/Rollout to 5\.14\.0 was aborted/)).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('host-reported text is plain text and unknown reasons render raw', () => {
    const evil = '<img src=x onerror=alert(1)>';
    renderPanel(
      paused({ rolled_back_hosts: [{ host: evil, reason: '<b>boom</b>', at: '2026-10-23T11:59:00Z' }] }),
    );
    const row = screen.getByRole('row', { name: /onerror/ });
    expect(row.querySelector('img, b')).toBeNull();
    expect(row).toHaveTextContent(evil);
    expect(row).toHaveTextContent('<b>boom</b>');
  });

  it('resume calls the endpoint only after confirming and updates the query data', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const resp: EnvOsquery = { target: null, counts: [], available: [], windows_hosts: 0, rollout: make() };
    api.resumeEnvRollout.mockResolvedValue(resp);
    renderPanel(paused());
    await user.click(screen.getByRole('button', { name: 'Resume rollout' }));
    expect(api.resumeEnvRollout).not.toHaveBeenCalled();
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Resume rollout' }));
    await waitFor(() => expect(api.resumeEnvRollout).toHaveBeenCalledWith('prod'));
    await waitFor(() => expect(qc.getQueryData(['env-osquery', 'prod'])).toEqual(resp));
  });

  it('abort explains the consequence, then calls the endpoint', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    api.abortEnvRollout.mockResolvedValue({ target: null, counts: [], available: [], windows_hosts: 0, rollout: make({ state: 'aborted' }) });
    renderPanel(make());
    await user.click(screen.getByRole('button', { name: 'Abort rollout' }));
    const dialog = await screen.findByRole('dialog');
    expect(api.abortEnvRollout).not.toHaveBeenCalled();
    expect(dialog).toHaveTextContent('Hosts already upgraded stay as they are');
    expect(dialog).toHaveTextContent('never move to 5.14.0');
    await user.click(within(dialog).getByRole('button', { name: 'Abort rollout' }));
    await waitFor(() => expect(api.abortEnvRollout).toHaveBeenCalledWith('prod'));
  });

  it('a 409 shows inline', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    api.resumeEnvRollout.mockRejectedValue(new Error('rollout is not paused'));
    renderPanel(paused());
    await user.click(screen.getByRole('button', { name: 'Resume rollout' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Resume rollout' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('rollout is not paused');
  });

  it('a past next_stage_at says shortly, not "about less than a minute"', () => {
    renderPanel(make({ next_stage_at: '2026-10-23T11:00:00Z' }));
    expect(screen.getByText('Widens to 50% shortly if nothing rolls back.')).toBeInTheDocument();
  });

  it('paused with an empty host list falls back to the paused host row', () => {
    renderPanel(paused({ rolled_back_hosts: [], counts: { eligible: 1, upgraded: 0, waiting: 0, rolled_back: 0 } }));
    expect(screen.getByRole('status')).toHaveTextContent('1 host rolled back');
    expect(screen.getByRole('row', { name: /web-prod-114/ })).toBeInTheDocument();
  });

  it('an out-of-range stage never renders undefined%', () => {
    renderPanel(paused({ stage: 9 }));
    expect(screen.getByRole('status')).not.toHaveTextContent('undefined');
  });

  it('a 409 refetches the real state', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const spy = vi.spyOn(qc, 'invalidateQueries');
    api.resumeEnvRollout.mockRejectedValue(new Error('rollout is not paused'));
    renderPanel(paused());
    await user.click(screen.getByRole('button', { name: 'Resume rollout' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Resume rollout' }));
    await screen.findByRole('alert');
    expect(spy).toHaveBeenCalledWith({ queryKey: ['env-osquery', 'prod'] });
  });

  it('abort updates the query data', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const resp: EnvOsquery = { target: null, counts: [], available: [], windows_hosts: 0, rollout: make({ state: 'aborted' }) };
    api.abortEnvRollout.mockResolvedValue(resp);
    renderPanel(make());
    await user.click(screen.getByRole('button', { name: 'Abort rollout' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Abort rollout' }));
    await waitFor(() => expect(qc.getQueryData(['env-osquery', 'prod'])).toEqual(resp));
  });

  it('double-clicking confirm calls the API once', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    api.abortEnvRollout.mockReturnValue(new Promise(() => {}));
    renderPanel(make());
    await user.click(screen.getByRole('button', { name: 'Abort rollout' }));
    await user.dblClick(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Abort rollout' }));
    expect(api.abortEnvRollout).toHaveBeenCalledTimes(1);
  });
});
