import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { LiveUpdatesProvider, createInvalidator, resourceRefetchInterval, useResourceUpdates } from './live-updates';

const mocks = vi.hoisted(() => ({ readEvents: vi.fn(), getFeatures: vi.fn() }));
vi.mock('$/api/events', () => ({ readEvents: mocks.readEvents }));
vi.mock('$/api/features', () => ({ getFeatures: mocks.getFeatures }));
afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); });

it('coalesces query invalidations and preserves other environments and domains', async () => {
  vi.useFakeTimers();
  const client = new QueryClient();
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  const live = createInvalidator(client, 'dev');
  for (let i = 0; i < 100; i++) live.add('queries', 'q');
  await vi.advanceTimersByTimeAsync(250);
  expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
    ['queries', 'dev'], ['query', 'dev', 'q'], ['query-results', 'dev', 'q'],
  ]);
  live.close(); client.clear();
});

it('uses change kinds to invalidate only affected query caches', async () => {
  vi.useFakeTimers();
  const client = new QueryClient();
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  const live = createInvalidator(client, 'dev');
  live.add('queries', 'q', 'metadata');
  live.add('queries', 'q', 'results');
  live.add('carves', 'c', 'files');
  await vi.advanceTimersByTimeAsync(250);
  expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
    ['queries', 'dev'], ['query', 'dev', 'q'], ['query-results', 'dev', 'q'],
    ['carve', 'dev', 'c'], ['carves', 'dev'],
  ]);
  live.close(); client.clear();
});

it('refetches after an in-flight snapshot so an invalidation cannot be lost', async () => {
  vi.useFakeTimers();
  const client = new QueryClient();
  let finish: () => void = () => undefined;
  vi.spyOn(client, 'isFetching').mockReturnValue(1);
  const invalidate = vi.spyOn(client, 'invalidateQueries').mockImplementationOnce(() => new Promise<void>(resolve => { finish = resolve; })).mockResolvedValue(undefined);
  const live = createInvalidator(client, 'dev');
  live.add('carves', 'c');
  await vi.advanceTimersByTimeAsync(250);
  const before = invalidate.mock.calls.filter(([f]) => f?.queryKey?.[0] === 'carves').length;
  finish();
  await vi.advanceTimersByTimeAsync(1);
  expect(invalidate.mock.calls.filter(([f]) => f?.queryKey?.[0] === 'carves')).toHaveLength(before + 1);
  live.close(); client.clear();
});

function QueriesConsumer() { useResourceUpdates('queries'); return null; }
function QueryStatusConsumer() {
  const live = useResourceUpdates('queries');
  return <div data-testid="queries-live">{live ? 'live' : 'polling'}</div>;
}

it('uses normal polling until the selected stream is connected', async () => {
  mocks.getFeatures.mockResolvedValue({ events: true, event_topics: ['queries'] });
  let receive: ((event: { event: string; data: Record<string, unknown> }) => void) | undefined;
  let closeStream: (() => void) | undefined;
  mocks.readEvents.mockImplementation((_env, _topics, _signal: AbortSignal, onEvent) => {
    receive = onEvent;
    return new Promise<void>(resolve => { closeStream = resolve; });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><LiveUpdatesProvider env="dev"><QueryStatusConsumer /></LiveUpdatesProvider></QueryClientProvider>);
  await waitFor(() => expect(mocks.readEvents).toHaveBeenCalledTimes(1));
  expect(screen.getByTestId('queries-live')).toHaveTextContent('polling');
  act(() => receive?.({ event: 'stream.ready', data: { environment_uuid: 'env-uuid' } }));
  expect(screen.getByTestId('queries-live')).toHaveTextContent('live');
  await act(async () => closeStream?.());
  await waitFor(() => expect(screen.getByTestId('queries-live')).toHaveTextContent('polling'));
  client.clear();
});

it('keeps polling intervals conservative for non-live and terminal resources', () => {
  expect(resourceRefetchInterval(false)).toBe(15_000);
  expect(resourceRefetchInterval(true)).toBe(60_000);
  expect(resourceRefetchInterval(true, { active: true, completed: false })).toBe(60_000);
  expect(resourceRefetchInterval(true, { active: false, completed: true })).toBe(false);
  expect(resourceRefetchInterval(false, { active: true, completed: false })).toBe(15_000);
});

it('shares one subscription and aborts the old environment on navigation and unmount', async () => {
  mocks.getFeatures.mockResolvedValue({ events: true, event_topics: ['queries'] });
  mocks.readEvents.mockImplementation((_env, _topics, signal: AbortSignal) => new Promise<void>(resolve => signal.addEventListener('abort', () => resolve())));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const tree = (env: string) => <QueryClientProvider client={client}><LiveUpdatesProvider env={env}><QueriesConsumer /><QueriesConsumer /></LiveUpdatesProvider></QueryClientProvider>;
  const view = render(tree('dev'));
  await waitFor(() => expect(mocks.readEvents).toHaveBeenCalledTimes(1));
  const oldSignal = mocks.readEvents.mock.calls[0][2] as AbortSignal;
  view.rerender(tree('production'));
  await waitFor(() => expect(mocks.readEvents).toHaveBeenCalledTimes(2));
  expect(oldSignal.aborted).toBe(true);
  expect(mocks.readEvents.mock.calls[1][0]).toBe('production');
  view.unmount();
  expect((mocks.readEvents.mock.calls[1][2] as AbortSignal).aborted).toBe(true);
  await act(async () => undefined);
  client.clear();
});

it('keeps legacy polling-only deployments free of event connections', async () => {
  mocks.getFeatures.mockResolvedValue({});
  const client = new QueryClient();
  const view = render(<QueryClientProvider client={client}><LiveUpdatesProvider env="dev"><QueriesConsumer /></LiveUpdatesProvider></QueryClientProvider>);
  await waitFor(() => expect(mocks.getFeatures).toHaveBeenCalled());
  expect(mocks.readEvents).not.toHaveBeenCalled();
  view.unmount(); client.clear();
});
