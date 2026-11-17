/**
 * Changes held for a second admin. An approved change is applied by its
 * requester sending the stored request again, unchanged.
 */
import { apiFetch } from './client';

export type ChangeStatus = 'pending' | 'approved' | 'denied' | 'applied' | 'expired';

export interface PendingChange {
  id: number;
  created_at: string;
  action: string;
  method: string;
  path: string;
  body: string;
  requested_by: string;
  status: ChangeStatus;
  decided_by?: string;
  decided_at?: string;
  expires_at: string;
  mine: boolean;
}

export const changesQueryKey = (env: string) => ['changes', env] as const;

/** GET /api/v1/changes/{env} */
export function listChanges(env: string): Promise<PendingChange[]> {
  return apiFetch<PendingChange[]>(`/api/v1/changes/${encodeURIComponent(env)}`);
}

/** POST /api/v1/changes/{env}/{id}/decision */
export function decideChange(env: string, id: number, decision: 'approve' | 'deny'): Promise<PendingChange> {
  return apiFetch<PendingChange>(`/api/v1/changes/${encodeURIComponent(env)}/${id}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision }),
  });
}

/** Sends the approved request again; the server matches it byte for byte. */
export function applyChange(c: PendingChange): Promise<unknown> {
  return apiFetch<unknown>(c.path, {
    method: c.method,
    headers: { 'Content-Type': 'application/json' },
    body: c.body || undefined,
  });
}
