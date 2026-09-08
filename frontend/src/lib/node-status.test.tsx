import { act, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider, focusManager } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import type { PropsWithChildren } from 'react';
import { useInactiveHours } from './node-status';

const getHours = vi.hoisted(() => vi.fn());
vi.mock('$/api/environments', () => ({ getEnvironmentInactiveHours: getHours }));

afterEach(() => {
  focusManager.setFocused(undefined);
  vi.useRealTimers();
});

it('refreshes an open screen every 30 seconds and pauses polling in the background', async () => {
  vi.useFakeTimers();
  focusManager.setFocused(true);
  getHours.mockResolvedValue({ override_hours: null, inactive_hours: 72, source: 'default' });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result, unmount } = renderHook(() => useInactiveHours('dev'), {
    wrapper: ({ children }: PropsWithChildren) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>,
  });
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(result.current.data?.inactive_hours).toBe(72);
  getHours.mockResolvedValue({ override_hours: 24, inactive_hours: 24, source: 'environment' });
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(result.current.data?.inactive_hours).toBe(24);
  focusManager.setFocused(false);
  getHours.mockResolvedValue({ override_hours: 168, inactive_hours: 168, source: 'environment' });
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(result.current.data?.inactive_hours).toBe(24);
  focusManager.setFocused(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(result.current.data?.inactive_hours).toBe(168);
  unmount();
  qc.clear();
});
