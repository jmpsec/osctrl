import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.mock('./client', () => ({
  apiFetch: (...args: unknown[]) => mockFetch(...args),
}));

import {
  getNodeVulns,
  getVulnAdvisory,
  listVulnFindings,
  requestVulnSync,
} from './vulnerabilities';

describe('vulnerabilities API client', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({});
  });

  it('omits unset and false filters from the findings query', async () => {
    await listVulnFindings('dev', { severity: 'critical', kev: false, state: 'open', page: 2, page_size: 50 });
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/v1/vulnerabilities/dev/findings?severity=critical&state=open&page=2&page_size=50',
    );
  });

  it('sends kev only when it narrows the list', async () => {
    await listVulnFindings('dev', { kev: true });
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/vulnerabilities/dev/findings?kev=true');
  });

  it('requests findings without a query string when nothing is filtered', async () => {
    await listVulnFindings('dev');
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/vulnerabilities/dev/findings');
  });

  // Red Hat ids contain ":"; GHSA-style ids could contain "/". Unencoded,
  // either one changes the path the API matches.
  it('encodes advisory ids', async () => {
    await getVulnAdvisory('dev', 'RHSA-2026:76750');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/vulnerabilities/dev/advisories/RHSA-2026%3A76750');
    await getVulnAdvisory('dev', 'GHSA-x/y');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/vulnerabilities/dev/advisories/GHSA-x%2Fy');
  });

  it('encodes the environment and node in the node route', async () => {
    await getNodeVulns('my env', 'ABC-1');
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/nodes/my%20env/node/ABC-1/vulnerabilities');
  });

  it('requests a sync with a POST', async () => {
    await requestVulnSync();
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/vulnerabilities/feeds/sync', { method: 'POST' });
  });
});
