import { apiFetch } from './client';

export interface ScimStatus {
  enabled: boolean;
  token_created_at?: string;
}

export interface UserGroups {
  groups: string[];
  updated_at?: string;
  /** SCIM provisions the user, so SSO logins leave the groups alone. */
  scim: boolean;
}

export const scimStatusKey = ['scim-status'] as const;

export function getScimStatus(): Promise<ScimStatus> {
  return apiFetch<ScimStatus>('/api/v1/scim');
}

export function rotateScimToken(): Promise<{ token: string }> {
  return apiFetch<{ token: string }>('/api/v1/scim/token', { method: 'POST' });
}

export function removeScimToken(): Promise<void> {
  return apiFetch<void>('/api/v1/scim/token', { method: 'DELETE' });
}

export function getUserGroups(username: string): Promise<UserGroups> {
  return apiFetch<UserGroups>(`/api/v1/users/${encodeURIComponent(username)}/groups`);
}
