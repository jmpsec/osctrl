/**
 * Settings API client.
 *
 * Reuses the existing GET endpoints for read-side; adds a PATCH for single
 * setting writes.
 */
import { apiFetch } from './client';

export type SettingType = 'string' | 'boolean' | 'integer';

/** Wire shape matching pkg/settings.SettingValue (subset). */
export interface SettingValue {
  ID: number;
  CreatedAt: string;
  UpdatedAt: string;
  Name: string;
  Service: string;
  EnvironmentID: number;
  JSON: boolean;
  Type: SettingType;
  String: string;
  Boolean: boolean;
  Integer: number;
  Info: string;
}

/** GET /api/v1/settings — every setting across all services (super-admin). */
export function listAllSettings(): Promise<SettingValue[]> {
  return apiFetch<SettingValue[]>('/api/v1/settings');
}

/** GET /api/v1/settings/{service} — non-JSON settings for one service. */
export function listServiceSettings(service: string): Promise<SettingValue[]> {
  return apiFetch<SettingValue[]>(`/api/v1/settings/${encodeURIComponent(service)}`);
}

/** GET /api/v1/settings/{service}/json — JSON-typed settings only. */
export function listServiceJSONSettings(service: string): Promise<SettingValue[]> {
  return apiFetch<SettingValue[]>(`/api/v1/settings/${encodeURIComponent(service)}/json`);
}

export interface SettingPatchRequest {
  type?: SettingType;
  string?: string;
  boolean?: boolean;
  integer?: number;
}

/** PATCH /api/v1/settings/{service}/{name}. */
export function patchSetting(
  service: string,
  name: string,
  body: SettingPatchRequest,
): Promise<SettingValue> {
  return apiFetch<SettingValue>(
    `/api/v1/settings/${encodeURIComponent(service)}/${encodeURIComponent(name)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}
