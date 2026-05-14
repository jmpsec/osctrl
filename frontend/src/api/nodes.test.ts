import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { listNodes } from './nodes';

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

const STUB_RESPONSE = {
  items: [],
  page: 1,
  page_size: 50,
  total_items: 0,
  total_pages: 0,
};

describe('listNodes — URL construction', () => {
  beforeEach(() => {
    mockApiFetch.mockResolvedValue(STUB_RESPONSE);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('builds the base URL without optional params', async () => {
    await listNodes({ env: 'prod' });
    expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/nodes/prod', undefined);
  });

  it('adds status=active when status is active', async () => {
    await listNodes({ env: 'prod', status: 'active' });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.get('status')).toBe('active');
  });

  it('does NOT add status param when status is "all"', async () => {
    await listNodes({ env: 'prod', status: 'all' });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.has('status')).toBe(false);
  });

  it('adds q param for search', async () => {
    await listNodes({ env: 'staging', q: 'web-server' });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.get('q')).toBe('web-server');
  });

  it('adds sort and dir params together', async () => {
    await listNodes({ env: 'dev', sort: 'hostname', dir: 'asc' });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.get('sort')).toBe('hostname');
    expect(params.get('dir')).toBe('asc');
  });

  it('adds page and page_size params', async () => {
    await listNodes({ env: 'prod', page: 3, pageSize: 100 });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.get('page')).toBe('3');
    expect(params.get('page_size')).toBe('100');
  });

  it('encodes special characters in env name', async () => {
    await listNodes({ env: 'my env' });
    const url: string = mockApiFetch.mock.calls[0][0];
    expect(url).toContain('my%20env');
  });

  it('combines multiple params correctly', async () => {
    await listNodes({
      env: 'prod',
      status: 'inactive',
      q: 'db',
      sort: 'lastseen',
      dir: 'desc',
      page: 2,
      pageSize: 25,
    });
    const url: string = mockApiFetch.mock.calls[0][0];
    const params = new URL(url, 'http://x').searchParams;
    expect(params.get('status')).toBe('inactive');
    expect(params.get('q')).toBe('db');
    expect(params.get('sort')).toBe('lastseen');
    expect(params.get('dir')).toBe('desc');
    expect(params.get('page')).toBe('2');
    expect(params.get('page_size')).toBe('25');
  });
});
