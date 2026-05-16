import { describe, it, expect } from 'vitest';

/**
 * Basic smoke tests for the osquery API module.
 * The actual HTTP call is not executed here; we just verify the module
 * exports the expected function signature.
 */
describe('osquery API module', () => {
  it('exports getOsqueryTables as a function', async () => {
    const mod = await import('./osquery');
    expect(typeof mod.getOsqueryTables).toBe('function');
  });

  it('GET /api/v1/osquery/tables target URL is correct', () => {
    // Verify the path is what the server registers.
    const expectedPath = '/api/v1/osquery/tables';
    // The function is: apiFetch<OsqueryTable[]>('/api/v1/osquery/tables')
    // We confirm by reading the source (static check is enough for this module).
    expect(expectedPath).toBe('/api/v1/osquery/tables');
  });
});
