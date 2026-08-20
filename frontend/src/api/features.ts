import { apiFetch } from './client';

export interface Features {
  posture: boolean;
  service_config: boolean;
  log_sinks?: boolean;
  auth_providers?: boolean;
  accelerated: boolean;
  console?: boolean;
  file_explorer: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
