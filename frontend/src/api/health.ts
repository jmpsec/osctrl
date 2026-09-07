/**
 * Health API client.
 *
 * One request returns every component plus upgrade status, so the page's
 * drill-downs expand what is already loaded instead of fetching again.
 */
import { apiFetch } from './client';

export type HealthStatusValue =
  | 'operational'
  | 'degraded'
  | 'down'
  | 'stale'
  | 'unknown';

export interface HealthComponent {
  id: string;
  name: string;
  status: HealthStatusValue;
  summary: string;
  details?: Record<string, unknown>;
}

export interface UpgradeInfo {
  current: string;
  suggested?: string;
  latest?: string;
  up_to_date: boolean;
  checked: boolean;
  checked_at?: string;
  more_information?: string;
  api_version?: string;
  tls_version?: string;
  skew: boolean;
}

export interface HealthStatus {
  generated_at: string;
  components: HealthComponent[];
  upgrade: UpgradeInfo;
}

/** GET /api/v1/health/status — admin only, 503 when --health-enabled is off. */
export function getHealthStatus(): Promise<HealthStatus> {
  return apiFetch<HealthStatus>('/api/v1/health/status');
}
