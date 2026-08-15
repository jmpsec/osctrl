import { apiFetch } from './client';

export interface Features {
  posture: boolean;
  service_config: boolean;
  accelerated: boolean;
  file_explorer: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
