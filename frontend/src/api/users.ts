import { apiFetch, ApiError } from './client';
import type {
  AdminUser,
  EnvAccess,
  GetPermissionsResponse,
  SetPermissionsAllResponse,
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

/** GET /api/v1/users/{username}/permissions — full env→access map. */
export function getUserPermissions(username: string): Promise<GetPermissionsResponse> {
  return apiFetch<GetPermissionsResponse>(
    `/api/v1/users/${encodeURIComponent(username)}/permissions`,
  );
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

// Reported by the bulk-set helper so the UI can render
// "applied to N of M environments." When the bulk endpoint is
// reachable, succeeded == failed.length === 0 and total == updated
// in a single round-trip. When falling back to the per-env loop, the
// counts reflect what the loop achieved before any abort.
export type BulkSetReport = {
  total: number;
  succeeded: number;
  failed: { envUuid: string; reason: string }[];
  // usedBulkEndpoint == true when the single POST succeeded.
  // false when we fell back to per-env calls (older api without the
  // /permissions/all route, or bulk returned non-404 5xx and the
  // caller asked for fallback).
  usedBulkEndpoint: boolean;
};

// setUserPermissionsAllSafe applies the same EnvAccess to every env.
//
// Strategy:
//   1. Try POST /api/v1/users/{u}/permissions/all (one round-trip).
//   2. If the api returns 404 — the operator is talking to an older
//      build without the bulk route — fall back to looping per-env
//      with the existing setUserPermissions.
//   3. Any other error (5xx, 4xx other than 404) propagates: callers
//      decide whether to retry via the loop or surface the error.
//
// envUuids is the list of envs to apply to. Passing an empty array
// is a no-op (returns total=0, succeeded=0). Concurrency is capped
// at `concurrency` (default 8) so the per-env fallback doesn't fan
// out hundreds of simultaneous fetches.
//
// signal is an AbortSignal so the caller's "Cancel" button can stop
// in-flight work. When aborted mid-loop, succeeded reflects the
// envs that completed before the cancellation.
export async function setUserPermissionsAllSafe(
  username: string,
  access: EnvAccess,
  envUuids: string[],
  opts: { concurrency?: number; signal?: AbortSignal } = {},
): Promise<BulkSetReport> {
  const total = envUuids.length;
  const concurrency = Math.max(1, opts.concurrency ?? 8);

  // Try the bulk endpoint first.
  try {
    const body = { access };
    const res = await apiFetch<SetPermissionsAllResponse>(
      `/api/v1/users/${encodeURIComponent(username)}/permissions/all`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: opts.signal,
      },
    );
    return {
      total: res.total,
      succeeded: res.updated,
      failed: [],
      usedBulkEndpoint: true,
    };
  } catch (e) {
    // Fall back ONLY on 404 (route not implemented on this api
    // build). Every other error — including network-level failures
    // and 5xx — surfaces to the caller. The caller can retry via
    // the loop explicitly if it wants to.
    if (!(e instanceof ApiError) || e.status !== 404) {
      throw e;
    }
  }

  // Fallback path: per-env loop with bounded concurrency.
  const failed: { envUuid: string; reason: string }[] = [];
  let succeeded = 0;
  // Slice into batches of `concurrency`. We don't use a fancy work-
  // stealing pool because the user-facing op is "apply to N envs",
  // not "saturate the link" — simple is fine.
  for (let i = 0; i < envUuids.length; i += concurrency) {
    if (opts.signal?.aborted) {
      break;
    }
    const batch = envUuids.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map((envUuid) =>
        setUserPermissions(username, { env_uuid: envUuid, access }),
      ),
    );
    results.forEach((r, idx) => {
      if (r.status === 'fulfilled') {
        succeeded++;
      } else {
        const reason =
          r.reason instanceof Error ? r.reason.message : String(r.reason);
        failed.push({ envUuid: batch[idx]!, reason });
      }
    });
  }
  return {
    total,
    succeeded,
    failed,
    usedBulkEndpoint: false,
  };
}

/** Payload accepted by the backend's UserActionHandler "add"/"remove" cases. */
export interface CreateUserBody {
  username: string;
  password: string;
  email?: string;
  fullname?: string;
  admin?: boolean;
  service?: boolean;
}

/** POST /api/v1/users/{username}/add — create a new operator (super-admin only).
 *
 * The api accepts the username in BOTH the URL and the body; they must match
 * (UserActionHandler validates this). We send the canonical lowercase form
 * in the URL and a verbatim copy in the body.
 */
export function createUser(body: CreateUserBody): Promise<{ data: string }> {
  return apiFetch<{ data: string }>(
    `/api/v1/users/${encodeURIComponent(body.username)}/add`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: body.username,
        password: body.password,
        email: body.email ?? '',
        fullname: body.fullname ?? '',
        admin: body.admin ?? false,
        service: body.service ?? false,
        environments: [],
      }),
    },
  );
}

/** POST /api/v1/users/{username}/remove — delete an operator (super-admin only).
 *
 * The api refuses to delete the current operator (self-deletion is blocked
 * server-side in UserActionHandler). Frontend should also hide the delete
 * affordance on the row for the logged-in user.
 */
export function deleteUser(username: string): Promise<{ data: string }> {
  return apiFetch<{ data: string }>(
    `/api/v1/users/${encodeURIComponent(username)}/remove`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
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
