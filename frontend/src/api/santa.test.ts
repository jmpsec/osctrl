import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.mock('./client', () => ({
  apiFetch: (...args: unknown[]) => mockFetch(...args),
}));

import {
  createSantaRule, deleteSantaRule, getSantaConfig, listSantaEvents, listSantaMachines, listSantaRules,
  putSantaConfig, rotateSantaToken, santaQueryKey,
} from './santa';

describe('santa API client', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({});
  });

  it('reads through the env-scoped routes', async () => {
    await getSantaConfig('a/b');
    await listSantaRules('dev');
    await listSantaMachines('dev');
    await listSantaEvents('dev', 2, 10);
    expect(mockFetch.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/santa/a%2Fb/config',
      '/api/v1/santa/dev/rules',
      '/api/v1/santa/dev/machines',
      '/api/v1/santa/dev/events?page=2&page_size=10',
    ]);
  });

  it('sends JSON bodies and verbs for writes', async () => {
    const cfg = {
      client_mode: 'LOCKDOWN' as const, batch_size: 0, enable_transitive_rules: true,
      removable_media: 'BLOCK' as const, removable_media_flags: [], encrypted_removable_media: '' as const, encrypted_removable_media_flags: [],
    };
    await putSantaConfig('dev', cfg);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/config', expect.objectContaining({ method: 'PUT', body: JSON.stringify(cfg) }));
    await rotateSantaToken('dev');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/token', { method: 'POST' });
    await deleteSantaRule('dev', 7);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/rules/7', { method: 'DELETE' });
    const rule = {
      identifier: 'x', rule_type: 'BINARY' as const, policy: 'ALLOWLIST' as const, cel_expr: '', custom_msg: '',
      custom_url: '', scope: 'env' as const, scope_value: '',
    };
    await createSantaRule('dev', rule);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/rules', expect.objectContaining({ method: 'POST', body: JSON.stringify(rule) }));
  });

  it('builds env-scoped query keys', () => {
    expect(santaQueryKey('dev', 'rules')).toEqual(['santa', 'dev', 'rules']);
  });
});
