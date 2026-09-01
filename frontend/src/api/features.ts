import { apiFetch } from './client';

export interface Features {
  posture: boolean;
  service_config: boolean;
  log_sinks?: boolean;
  auth_providers?: boolean;
  /** Alerting subsystem (--alerts-enabled). When false the alerts
   * routes are absent and the SPA hides the Alerts section. */
  alerts?: boolean;
  accelerated: boolean;
  console?: boolean;
  file_explorer: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
