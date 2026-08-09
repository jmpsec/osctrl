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
  Type: SettingType;
  String: string;
  Boolean: boolean;
  Integer: number;
  Info: string;
}

/** GET /api/v1/settings/{service} — settings for one service. */
export function listServiceSettings(service: string): Promise<SettingValue[]> {
  return apiFetch<SettingValue[]>(`/api/v1/settings/${encodeURIComponent(service)}`);
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
