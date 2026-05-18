/**
 * Sample / starter library client.
 *
 * Both endpoints require authentication. Earlier revisions exposed them
 * pre-auth on the rationale that the data is static and ships with the
 * binary, but a pentest finding pointed out that the carve target list
 * (/etc/passwd, \Windows\System32\config\SAM, etc.) is exactly the
 * shopping list an attacker wants, and that responses fingerprint the
 * deployment as osctrl. The only consumers are post-login forms
 * (queries/new and carves/new), so requiring auth costs us nothing.
 *
 * Mirrors pkg/queries.QuerySample and pkg/carves.CarveSample on the Go side.
 */
import { apiFetch } from './client';

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

export async function listQuerySamples(): Promise<QuerySample[]> {
  return apiFetch<QuerySample[]>('/api/v1/queries/samples');
}

export async function listCarveSamples(): Promise<CarveSample[]> {
  return apiFetch<CarveSample[]>('/api/v1/carves/samples');
}
