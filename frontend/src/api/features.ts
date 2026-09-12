import { apiFetch } from './client';

export interface Features {
  events?: boolean;
  event_topics?: string[];
  posture: boolean;
  service_config: boolean;
  log_sinks?: boolean;
  auth_providers?: boolean;
  /** Alerting subsystem (--alerts-enabled). When false the alerts
   * routes are absent and the SPA hides the Alerts section. */
  alerts?: boolean;
  /** Health/system status (--health-enabled). When false the health routes
   * are absent and the SPA hides the Health section. */
  health?: boolean;
  accelerated: boolean;
  console?: boolean;
  file_explorer: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
