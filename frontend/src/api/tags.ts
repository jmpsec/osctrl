import { apiFetch } from './client';
import type { AdminTag, TagsActionRequest } from './types';

/** GET /api/v1/tags — all tags across all environments (super-admin only). */
export function listAllTags(): Promise<AdminTag[]> {
  return apiFetch<AdminTag[]>('/api/v1/tags');
}

/** GET /api/v1/tags/{env} — env-scoped list of tags. */
export function listEnvTags(env: string): Promise<AdminTag[]> {
  return apiFetch<AdminTag[]>(`/api/v1/tags/${encodeURIComponent(env)}`);
}

/** GET /api/v1/tags/{env}/{name} — single tag. */
export function getEnvTag(env: string, name: string): Promise<AdminTag> {
  return apiFetch<AdminTag>(
    `/api/v1/tags/${encodeURIComponent(env)}/${encodeURIComponent(name)}`,
  );
}

export type TagAction = 'add' | 'edit' | 'remove';

interface TagActionResponse {
  data: string;
}

/** POST /api/v1/tags/{env}/{action} — create / update / delete tags. */
export function tagsAction(
  env: string,
  action: TagAction,
  body: TagsActionRequest,
): Promise<TagActionResponse> {
  return apiFetch<TagActionResponse>(
    `/api/v1/tags/${encodeURIComponent(env)}/${encodeURIComponent(action)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/**
 * POST /api/v1/nodes/{env}/tag — assign a tag to a node. The nodes
 * multi-action menu calls this once per selected UUID via Promise.allSettled.
 */
export interface NodeTagRequest {
  uuid: string;
  tag: string;
  type?: number;
  custom?: string;
}

export function tagNode(env: string, body: NodeTagRequest): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/nodes/${encodeURIComponent(env)}/tag`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}
