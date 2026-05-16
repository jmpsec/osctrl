/**
 * Sample / starter library client.
 *
 * Both endpoints are pre-auth: the data is static, ships with the binary, and
 * isn't tenant- or env-scoped. The login screen can lazy-load them; so can
 * the queries/new and carves/new forms.
 *
 * Mirrors pkg/queries.QuerySample and pkg/carves.CarveSample on the Go side.
 */

export type QuerySamplePlatform = 'linux' | 'darwin' | 'windows';

export type QuerySampleCategory =
  | 'recon'
  | 'processes'
  | 'users'
  | 'network'
  | 'persistence'
  | 'file_integrity'
  | 'packages';

export interface QuerySample {
  name: string;
  description: string;
  sql: string;
  category: QuerySampleCategory;
  platforms: QuerySamplePlatform[];
}

export type CarveSamplePlatform = 'linux' | 'darwin' | 'windows';

export type CarveSampleCategory =
  | 'auth'
  | 'logs'
  | 'registry'
  | 'keychain'
  | 'history'
  | 'config';

export interface CarveSample {
  label: string;
  path: string;
  platform: CarveSamplePlatform;
  category: CarveSampleCategory;
  notes: string;
}

/**
 * Bypass apiFetch — endpoint is unauthenticated and the 401→/login redirect
 * inside apiFetch would create a redirect loop if it ever fired (it can't
 * here, but: belt-and-braces — same pattern as listLoginEnvironments).
 */
export async function listQuerySamples(): Promise<QuerySample[]> {
  const res = await fetch('/api/v1/queries/samples', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to load query samples (HTTP ${res.status})`);
  }
  return (await res.json()) as QuerySample[];
}

export async function listCarveSamples(): Promise<CarveSample[]> {
  const res = await fetch('/api/v1/carves/samples', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to load carve samples (HTTP ${res.status})`);
  }
  return (await res.json()) as CarveSample[];
}
