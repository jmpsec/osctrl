import { apiFetch } from './client';

export interface Features {
  posture: boolean;
  service_config: boolean;
  /** Tied to the same flag as service_config — log sink routes are
   * registered alongside the service-config routes. Optional so partial
   * test mocks keep compiling across feature additions. */
  log_sinks?: boolean;
  accelerated: boolean;
  console?: boolean;
  file_explorer: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
