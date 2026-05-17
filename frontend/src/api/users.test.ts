import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { setUserPermissionsAllSafe } from './users';
import { ApiError } from './client';

// Pin the bulk-vs-fallback decision tree. The client function is
// load-bearing for the "Apply to all environments" UX: it must
// prefer the single-shot endpoint when available and silently fall
// back to a per-env loop when the api is older (404 on
// /permissions/all). Any other error must propagate — we don't want
// the SPA to silently retry on a 5xx that would also fail in the
// fallback path.

const originalFetch = globalThis.fetch;

beforeEach(() => {
  globalThis.fetch = vi.fn() as unknown as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function mockFetch(impl: (url: string, init?: RequestInit) => Response) {
  (globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(
    (input: RequestInfo, init?: RequestInit) => Promise.resolve(impl(String(input), init)),
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('setUserPermissionsAllSafe', () => {
  it('uses the bulk endpoint on the happy path (single round-trip)', async () => {
    let calls = 0;
    mockFetch((url) => {
      calls++;
      expect(url).toContain('/permissions/all');
      return jsonResponse(200, {
        updated: 7,
        total: 7,
        access: { user: true, query: false, carve: false, admin: false },
      });
    });

    const report = await setUserPermissionsAllSafe(
      'alice',
      { user: true, query: false, carve: false, admin: false },
      ['env-1', 'env-2', 'env-3', 'env-4', 'env-5', 'env-6', 'env-7'],
    );

    expect(calls).toBe(1);
    expect(report.usedBulkEndpoint).toBe(true);
    expect(report.total).toBe(7);
    expect(report.succeeded).toBe(7);
    expect(report.failed).toEqual([]);
  });

  it('falls back to per-env loop when the bulk endpoint returns 404', async () => {
    // Older api: doesn't know /permissions/all → 404. Falls back to
    // looping POST /permissions per env. Each per-env call returns
    // 200.
    let bulkCall = 0;
    let perEnvCalls = 0;
    mockFetch((url) => {
      if (url.endsWith('/permissions/all')) {
        bulkCall++;
        return jsonResponse(404, { error: 'route not found' });
      }
      if (url.endsWith('/permissions')) {
        perEnvCalls++;
        return jsonResponse(200, { user: true });
      }
      return new Response('unexpected url', { status: 500 });
    });

    const envs = ['a', 'b', 'c'];
    const report = await setUserPermissionsAllSafe(
      'alice',
      { user: true, query: false, carve: false, admin: false },
      envs,
    );

    expect(bulkCall).toBe(1);
    expect(perEnvCalls).toBe(3);
    expect(report.usedBulkEndpoint).toBe(false);
    expect(report.total).toBe(3);
    expect(report.succeeded).toBe(3);
    expect(report.failed).toEqual([]);
  });

  it('records per-env failures in fallback mode without aborting the rest', async () => {
    // env-2 fails — but env_uuid travels in the request body, not
    // the URL, so we have to parse the body to dispatch the mock.
    mockFetch((url, init) => {
      if (url.endsWith('/permissions/all')) {
        return jsonResponse(404, {});
      }
      const body = init?.body ? JSON.parse(init.body as string) : {};
      if (body.env_uuid === 'env-2') {
        return jsonResponse(500, { error: 'internal' });
      }
      return jsonResponse(200, { user: true });
    });

    const report = await setUserPermissionsAllSafe(
      'alice',
      { user: true, query: false, carve: false, admin: false },
      ['env-1', 'env-2', 'env-3'],
    );

    expect(report.usedBulkEndpoint).toBe(false);
    expect(report.total).toBe(3);
    expect(report.succeeded).toBe(2);
    expect(report.failed).toHaveLength(1);
    expect(report.failed[0]?.envUuid).toBe('env-2');
  });

  it('propagates non-404 errors from the bulk endpoint (does NOT silently retry)', async () => {
    // Bulk returns 500. The caller — not the client — decides
    // whether to retry. Silent fallback would mask the real error.
    let perEnvCalls = 0;
    mockFetch((url) => {
      if (url.endsWith('/permissions/all')) {
        return jsonResponse(500, { error: 'database is down' });
      }
      perEnvCalls++;
      return jsonResponse(200, {});
    });

    await expect(
      setUserPermissionsAllSafe(
        'alice',
        { user: true, query: false, carve: false, admin: false },
        ['env-1', 'env-2'],
      ),
    ).rejects.toBeInstanceOf(ApiError);

    expect(perEnvCalls).toBe(0); // no fallback fired
  });

  it('returns zero counts on empty env list (no api calls)', async () => {
    // Empty env list is still allowed — the bulk path is tried first
    // (it'll succeed against the api with total=0,updated=0).
    mockFetch((url) => {
      expect(url).toContain('/permissions/all');
      return jsonResponse(200, { updated: 0, total: 0, access: { user: false, query: false, carve: false, admin: false } });
    });
    const report = await setUserPermissionsAllSafe(
      'alice',
      { user: false, query: false, carve: false, admin: false },
      [],
    );
    expect(report.total).toBe(0);
    expect(report.succeeded).toBe(0);
  });
});
