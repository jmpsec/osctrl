/**
 * Osquery version upgrades: the package digest library (super admin), the
 * environment target (environment admin) and the per-node pin.
 */
import { apiFetch } from './client';
import type { EnvOsquery, NodeOsquery, OsqueryEntryRequest, OsqueryVersion } from './types';

const json = { 'Content-Type': 'application/json' };
const libPath = (version: string) => `/api/v1/osquery/versions/${encodeURIComponent(version)}`;
const envPath = (env: string) => `/api/v1/environments/osquery/${encodeURIComponent(env)}`;
const nodePath = (env: string, uuid: string) =>
  `/api/v1/nodes/${encodeURIComponent(env)}/node/${encodeURIComponent(uuid)}/osquery`;

export const osqueryVersionsQueryKey = ['osquery-versions'] as const;

export function listOsqueryVersions(): Promise<OsqueryVersion[]> {
  return apiFetch<OsqueryVersion[]>('/api/v1/osquery/versions');
}

export function putOsqueryVersion(version: string, entries: OsqueryEntryRequest[]): Promise<OsqueryVersion> {
  return apiFetch<OsqueryVersion>(libPath(version), {
    method: 'PUT',
    headers: json,
    body: JSON.stringify({ entries }),
  });
}

/** 409 while the version is assigned to an environment or host. */
export function deleteOsqueryVersion(version: string): Promise<void> {
  return apiFetch<void>(libPath(version), { method: 'DELETE' });
}

export function getEnvOsquery(env: string): Promise<EnvOsquery> {
  return apiFetch<EnvOsquery>(envPath(env));
}

export function setEnvOsquery(env: string, version: string): Promise<EnvOsquery> {
  return apiFetch<EnvOsquery>(envPath(env), { method: 'PUT', headers: json, body: JSON.stringify({ version }) });
}

export function clearEnvOsquery(env: string): Promise<EnvOsquery> {
  return apiFetch<EnvOsquery>(envPath(env), { method: 'DELETE' });
}

export function getNodeOsquery(env: string, uuid: string): Promise<NodeOsquery> {
  return apiFetch<NodeOsquery>(nodePath(env, uuid));
}

/** `expires_at`: RFC3339, or omitted for no expiry. */
export function pinNodeOsquery(env: string, uuid: string, version: string, expires_at?: string): Promise<NodeOsquery> {
  return apiFetch<NodeOsquery>(nodePath(env, uuid), {
    method: 'PUT',
    headers: json,
    body: JSON.stringify(expires_at ? { version, expires_at } : { version }),
  });
}

export function unpinNodeOsquery(env: string, uuid: string): Promise<NodeOsquery> {
  return apiFetch<NodeOsquery>(nodePath(env, uuid), { method: 'DELETE' });
}
