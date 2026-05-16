import { apiFetch } from './client';
import type {
  AdminUser,
  EnvAccess,
  SetPermissionsRequest,
  TokenResponse,
  UserMeResponse,
} from './types';

/** GET /api/v1/users — super-admin list of users. */
export function listUsers(): Promise<AdminUser[]> {
  return apiFetch<AdminUser[]>('/api/v1/users');
}

/** GET /api/v1/users/{username} — single user (super-admin). */
export function getUser(username: string): Promise<AdminUser> {
  return apiFetch<AdminUser>(`/api/v1/users/${encodeURIComponent(username)}`);
}

/** POST /api/v1/users/{username}/permissions — replace per-env access. */
export function setUserPermissions(
  username: string,
  body: SetPermissionsRequest,
): Promise<EnvAccess> {
  return apiFetch<EnvAccess>(
    `/api/v1/users/${encodeURIComponent(username)}/permissions`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/** POST /api/v1/users/{username}/token/refresh — mint a new API token. */
export function refreshUserToken(username: string): Promise<TokenResponse> {
  return apiFetch<TokenResponse>(
    `/api/v1/users/${encodeURIComponent(username)}/token/refresh`,
    { method: 'POST' },
  );
}

/** DELETE /api/v1/users/{username}/token — invalidate the user's API token. */
export function deleteUserToken(username: string): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/users/${encodeURIComponent(username)}/token`,
    { method: 'DELETE' },
  );
}

/** GET /api/v1/users/me — current operator's profile. */
export function getMe(): Promise<UserMeResponse> {
  return apiFetch<UserMeResponse>('/api/v1/users/me');
}

/** PATCH /api/v1/users/me — update own email and/or fullname. */
export function patchMe(body: { email?: string; fullname?: string }): Promise<UserMeResponse> {
  return apiFetch<UserMeResponse>('/api/v1/users/me', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** POST /api/v1/users/me/password — change own password. */
export function changeMyPassword(body: {
  current_password: string;
  new_password: string;
}): Promise<{ message: string }> {
  return apiFetch<{ message: string }>('/api/v1/users/me/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
