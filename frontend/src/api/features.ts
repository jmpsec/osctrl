import { apiFetch } from './client';

export interface Features {
  posture: boolean;
  accelerated: boolean;
}

export function getFeatures(): Promise<Features> {
  return apiFetch<Features>('/api/v1/features');
}
