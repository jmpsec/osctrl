import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.mock('./client', () => ({
  apiFetch: (...args: unknown[]) => mockFetch(...args),
}));

import {
  createSantaRule, decideSantaRequest, decideSantaRequestByLink, deleteSantaRule, getSantaConfig, getSantaRequest, listSantaEvents, listSantaMachines, listSantaRequests, listSantaRules,
  getSantaVotes, putSantaConfig, rotateSantaToken, santaQueryKey, voteSantaFile,
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
    await listSantaRequests('dev');
    await listSantaRequests('dev', 'pending');
    expect(mockFetch.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/santa/a%2Fb/config',
      '/api/v1/santa/dev/rules',
      '/api/v1/santa/dev/machines',
      '/api/v1/santa/dev/events?page=2&page_size=10',
      '/api/v1/santa/dev/requests',
      '/api/v1/santa/dev/requests?status=pending',
    ]);
  });

  it('sends JSON bodies and verbs for writes', async () => {
    const cfg = {
      client_mode: 'LOCKDOWN' as const, batch_size: 0, enable_transitive_rules: true,
      removable_media: 'BLOCK' as const, removable_media_flags: [], encrypted_removable_media: '' as const, encrypted_removable_media_flags: [],
      approval_url: 'https://osctrl.example.com', notify_channels: [3],
      vote_local_threshold: 2, vote_global_threshold: 5, override_file_access_action: 'DISABLE' as const,
      enable_bundles: true, enable_all_event_upload: false, disable_unknown_event_upload: false,
      allowed_path_regex: '', blocked_path_regex: '^/tmp/', event_detail_url: '', event_detail_text: '',
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

  it('posts a decision for one request', async () => {
    const body = { decision: 'approve' as const, scope: 'node' as const, scope_value: '', reason: '' };
    await decideSantaRequest('dev', 9, body);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/requests/9/decision', expect.objectContaining({ method: 'POST', body: JSON.stringify(body) }));
  });

  it('posts a link decision with the token in the body, never in the URL', async () => {
    await decideSantaRequestByLink('dev', 'TOKEN', { decision: 'deny', reason: 'no' });
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/requests/link', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ token: 'TOKEN', decision: 'deny', reason: 'no' }),
    }));
    await getSantaRequest('dev', 9);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/requests/9');
  });

  it('reads and casts votes', async () => {
    await getSantaVotes('dev', 'abc');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/votes?sha256=abc');
    const body = { sha256: 'abc', machine_id: 'M' };
    await voteSantaFile('dev', body);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/santa/dev/votes', expect.objectContaining({ method: 'POST', body: JSON.stringify(body) }));
  });

  it('builds env-scoped query keys', () => {
    expect(santaQueryKey('dev', 'rules')).toEqual(['santa', 'dev', 'rules']);
  });
});
