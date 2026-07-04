import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { getStats } from './stats';
import type { StatsResponse } from './stats';

// ---------------------------------------------------------------------------
// Mock apiFetch so we can capture the URL it's called with
// ---------------------------------------------------------------------------
const mockApiFetch = vi.fn();

vi.mock('./client', () => ({
  apiFetch: (url: string, init?: RequestInit) => mockApiFetch(url, init),
  getCsrfToken: () => null,
  setCsrfToken: vi.fn(),
  isAuthenticated: () => false,
}));

const STUB_RESPONSE: StatsResponse = {
  total_nodes: 10,
  active_nodes: 7,
  inactive_nodes: 3,
  inactive_hours: 72,
  total_active_queries: 2,
  total_active_carves: 1,
  platform_counts: { linux: 6, darwin: 2, windows: 2, other: 0 },
  environments: [
    {
      uuid: 'env-uuid-1',
      name: 'prod',
      active: 7,
      inactive: 3,
      total: 10,
      active_queries: 2,
      active_carves: 1,
      platform_counts: { linux: 6, darwin: 2, windows: 2, other: 0 },
    },
  ],
};

describe('getStats — URL construction', () => {
  beforeEach(() => {
    mockApiFetch.mockResolvedValue(STUB_RESPONSE);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('calls /api/v1/stats with no query params', async () => {
    await getStats();
    expect(mockApiFetch).toHaveBeenCalledTimes(1);
    // apiFetch signature is (path, init?) — getStats passes only the path,
    // so init is the default empty object (passed as undefined by our mock capture).
    const calledUrl: string = mockApiFetch.mock.calls[0][0] as string;
    expect(calledUrl).toBe('/api/v1/stats');
  });

  it('returns the response shape from apiFetch', async () => {
    const result = await getStats();
    expect(result.total_nodes).toBe(10);
    expect(result.active_nodes).toBe(7);
    expect(result.inactive_nodes).toBe(3);
    expect(result.total_active_queries).toBe(2);
    expect(result.total_active_carves).toBe(1);
    expect(result.environments).toHaveLength(1);
    expect(result.environments[0].uuid).toBe('env-uuid-1');
    expect(result.environments[0].name).toBe('prod');
  });

  it('propagates errors from apiFetch', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('network error'));
    await expect(getStats()).rejects.toThrow('network error');
  });
});
