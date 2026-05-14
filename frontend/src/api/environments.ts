/**
 * Environments API client.
 *
 * GET /api/v1/environments returns the raw env list (super-admin only).
 * CRUD + per-section config + intervals + expiration are additions.
 */
import { apiFetch } from './client';

/**
 * TLSEnvironment — full storage shape returned by the API. Mirrors
 * pkg/environments.TLSEnvironment's snake_case JSON tags.
 */
export interface TLSEnvironment {
  id: number;
  created_at: string;
  updated_at: string;
  uuid: string;
  name: string;
  hostname: string;
  secret: string;
  enroll_secret_path: string;
  enroll_expire: string;
  remove_secret_path: string;
  remove_expire: string;
  type: string;
  deb_package: string;
  rpm_package: string;
  msi_package: string;
  pkg_package: string;
  debug_http: boolean;
  icon: string;
  options: string;
  schedule: string;
  packs: string;
  decorators: string;
  atc: string;
  configuration: string;
  flags: string;
  certificate: string;
  config_tls: boolean;
  config_interval: number;
  logging_tls: boolean;
  log_interval: number;
  query_tls: boolean;
  query_interval: number;
  carves_tls: boolean;
  enroll_path: string;
  log_path: string;
  config_path: string;
  query_read_path: string;
  query_write_path: string;
  carver_init_path: string;
  carver_block_path: string;
  accept_enrolls: boolean;
  user_id: number;
}

export interface EnvCreateRequest {
  name: string;
  hostname: string;
  type?: string;
  icon?: string;
}

export interface EnvUpdateRequest {
  name?: string;
  hostname?: string;
  type?: string;
  icon?: string;
  debug_http?: boolean;
  accept_enrolls?: boolean;
}

export interface EnvConfigResponse {
  options: string;
  schedule: string;
  packs: string;
  decorators: string;
  atc: string;
  flags: string;
}

export interface EnvConfigPatchRequest {
  options?: string;
  schedule?: string;
  packs?: string;
  decorators?: string;
  atc?: string;
  flags?: string;
}

export interface EnvIntervalsPatchRequest {
  config_interval?: number;
  log_interval?: number;
  query_interval?: number;
}

export type EnvExpirationAction = 'extend' | 'expire' | 'rotate' | 'not-expire';

export interface EnvExpirationPatchRequest {
  action: EnvExpirationAction;
}

/** GET /api/v1/environments — list every environment (super-admin). */
export function listEnvironments(): Promise<TLSEnvironment[]> {
  return apiFetch<TLSEnvironment[]>('/api/v1/environments');
}

/** GET /api/v1/environments/{env} — single env (user-level permission). */
export function getEnvironment(env: string): Promise<TLSEnvironment> {
  return apiFetch<TLSEnvironment>(`/api/v1/environments/${encodeURIComponent(env)}`);
}

/** POST /api/v1/environments — create. */
export function createEnvironment(body: EnvCreateRequest): Promise<TLSEnvironment> {
  return apiFetch<TLSEnvironment>('/api/v1/environments', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** PATCH /api/v1/environments/{env} — partial update. */
export function updateEnvironment(
  env: string,
  body: EnvUpdateRequest,
): Promise<TLSEnvironment> {
  return apiFetch<TLSEnvironment>(`/api/v1/environments/${encodeURIComponent(env)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** DELETE /api/v1/environments/{env}. */
export function deleteEnvironment(env: string): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(`/api/v1/environments/${encodeURIComponent(env)}`, {
    method: 'DELETE',
  });
}

/** GET /api/v1/environments/config/{env} — six osquery config sections. */
export function getEnvironmentConfig(env: string): Promise<EnvConfigResponse> {
  return apiFetch<EnvConfigResponse>(
    `/api/v1/environments/config/${encodeURIComponent(env)}`,
  );
}

/** PATCH /api/v1/environments/config/{env} — atomic JSON-validated patch. */
export function patchEnvironmentConfig(
  env: string,
  body: EnvConfigPatchRequest,
): Promise<EnvConfigResponse> {
  return apiFetch<EnvConfigResponse>(
    `/api/v1/environments/config/${encodeURIComponent(env)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/** PATCH /api/v1/environments/intervals/{env} — config/log/query pull intervals. */
export function patchEnvironmentIntervals(
  env: string,
  body: EnvIntervalsPatchRequest,
): Promise<TLSEnvironment> {
  return apiFetch<TLSEnvironment>(
    `/api/v1/environments/intervals/${encodeURIComponent(env)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/** PATCH /api/v1/environments/expiration/{env} — extend/expire/rotate/not-expire. */
export function patchEnvironmentExpiration(
  env: string,
  body: EnvExpirationPatchRequest,
): Promise<TLSEnvironment> {
  return apiFetch<TLSEnvironment>(
    `/api/v1/environments/expiration/${encodeURIComponent(env)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}
