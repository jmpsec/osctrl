import { apiFetch } from './client';
import type { ServiceCommand } from './service-config';

export interface AuthProvider {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  type: string;
  enabled: boolean;
  config: unknown;
  source: string;
  info: string;
}

export interface AuthProviderTypeSpec {
  type: string;
  description: string;
  has_secret: boolean;
  secret_fields?: string[];
  fields?: AuthProviderFieldSpec[];
}

export interface AuthProviderFieldSpec {
  name: string;
  label: string;
  type: string;
  required: boolean;
  secret: boolean;
  placeholder?: string;
  help?: string;
  options?: string[];
  default?: unknown;
}

export function listAuthProviders(opts?: { reveal?: boolean }): Promise<AuthProvider[]> {
  const qs = opts?.reveal ? '?reveal=1' : '';
  return apiFetch<AuthProvider[]>(`/api/v1/auth-providers${qs}`);
}

export function listAuthProviderTypes(): Promise<AuthProviderTypeSpec[]> {
  return apiFetch<AuthProviderTypeSpec[]>('/api/v1/auth-providers/types');
}

export function getAuthProvider(id: number, reveal?: boolean): Promise<AuthProvider> {
  const qs = reveal ? '?reveal=1' : '';
  return apiFetch<AuthProvider>(`/api/v1/auth-providers/${id}${qs}`);
}

export interface AuthProviderCreateRequest {
  name: string;
  type: string;
  enabled: boolean;
  config: unknown;
  info?: string;
}

export function createAuthProvider(body: AuthProviderCreateRequest): Promise<AuthProvider> {
  return apiFetch<AuthProvider>('/api/v1/auth-providers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export interface AuthProviderUpdateRequest {
  name: string;
  type: string;
  enabled: boolean;
  config: unknown;
  info?: string;
}

export function updateAuthProvider(id: number, body: AuthProviderUpdateRequest): Promise<AuthProvider> {
  return apiFetch<AuthProvider>(`/api/v1/auth-providers/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function deleteAuthProvider(id: number): Promise<void> {
  return apiFetch<void>(`/api/v1/auth-providers/${id}`, { method: 'DELETE' });
}

export function revertAuthProvider(id: number): Promise<AuthProvider> {
  return apiFetch<AuthProvider>(`/api/v1/auth-providers/${id}/revert`, { method: 'POST' });
}

export function testAuthProvider(type: string, config: unknown): Promise<{ ok: boolean; error?: string }> {
  return apiFetch<{ ok: boolean; error?: string }>('/api/v1/auth-providers/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, config }),
  });
}

/** POST /api/v1/auth-providers/fetch-metadata — fetches IdP metadata XML from the given URL. */
export function fetchIdPMetadata(url: string): Promise<{ xml: string }> {
  return apiFetch<{ xml: string }>('/api/v1/auth-providers/fetch-metadata', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
}

export function applyAuthProviders(): Promise<{ message: string; service?: string; command?: ServiceCommand }> {
  return apiFetch('/api/v1/auth-providers/apply', { method: 'POST' });
}
