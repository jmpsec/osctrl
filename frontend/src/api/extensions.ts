/**
 * Extensions API client: the osquery extension library and its per-platform/arch
 * binaries (super admin only), plus environment and host assignments.
 */
import { apiFetch } from './client';
import type {
  EnvExtensions,
  Extension,
  ExtensionCreateRequest,
  ExtensionUpdateRequest,
  NodeExtensions,
} from './types';

const base = '/api/v1/extensions';
const json = { 'Content-Type': 'application/json' };

/** Query key shared by the page and anything that must refresh the library. */
export const extensionsQueryKey = ['extensions'] as const;

export function listExtensions(): Promise<Extension[]> {
  return apiFetch<Extension[]>(base);
}

export function createExtension(body: ExtensionCreateRequest): Promise<Extension> {
  return apiFetch<Extension>(base, { method: 'POST', headers: json, body: JSON.stringify(body) });
}

export function updateExtension(id: number, body: ExtensionUpdateRequest): Promise<Extension> {
  return apiFetch<Extension>(`${base}/${id}`, {
    method: 'PATCH',
    headers: json,
    body: JSON.stringify(body),
  });
}

export function deleteExtension(id: number): Promise<void> {
  return apiFetch<void>(`${base}/${id}`, { method: 'DELETE' });
}

/** PUT multipart (field `file`); the browser sets the multipart boundary. */
export function uploadExtensionFile(
  id: number,
  platform: string,
  arch: string,
  file: File,
): Promise<Extension> {
  const body = new FormData();
  body.append('file', file);
  return apiFetch<Extension>(`${base}/${id}/files/${platform}/${arch}`, { method: 'PUT', body });
}

export function deleteExtensionFile(id: number, platform: string, arch: string): Promise<void> {
  return apiFetch<void>(`${base}/${id}/files/${platform}/${arch}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

const envPath = (env: string) => `/api/v1/environments/extensions/${encodeURIComponent(env)}`;
const nodePath = (env: string, uuid: string) =>
  `/api/v1/nodes/${encodeURIComponent(env)}/node/${encodeURIComponent(uuid)}/extensions`;

export function getEnvExtensions(env: string): Promise<EnvExtensions> {
  return apiFetch<EnvExtensions>(envPath(env));
}

export function assignEnvExtension(env: string, id: number): Promise<EnvExtensions> {
  return apiFetch<EnvExtensions>(`${envPath(env)}/${id}`, { method: 'PUT' });
}

export function unassignEnvExtension(env: string, id: number): Promise<EnvExtensions> {
  return apiFetch<EnvExtensions>(`${envPath(env)}/${id}`, { method: 'DELETE' });
}

export function getNodeExtensions(env: string, uuid: string): Promise<NodeExtensions> {
  return apiFetch<NodeExtensions>(nodePath(env, uuid));
}

/** Super admin only. `expires_at` is required by the API: RFC3339, or null for no expiry. */
export function assignNodeExtension(
  env: string,
  uuid: string,
  id: number,
  expires_at: string | null,
): Promise<NodeExtensions> {
  return apiFetch<NodeExtensions>(`${nodePath(env, uuid)}/${id}`, {
    method: 'PUT',
    headers: json,
    body: JSON.stringify({ expires_at }),
  });
}

export function unassignNodeExtension(env: string, uuid: string, id: number): Promise<NodeExtensions> {
  return apiFetch<NodeExtensions>(`${nodePath(env, uuid)}/${id}`, { method: 'DELETE' });
}
