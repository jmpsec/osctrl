import { apiFetch } from './client';
import type {
  NodesPagedResponse,
  OsqueryNode,
  NodeLogsResponse,
  NodeStatus,
  NodeSort,
  SortDir,
} from './types';

/** Platform-bucket filter values accepted by GET /api/v1/nodes/{env}. */
export type NodePlatform = 'linux' | 'darwin' | 'windows' | 'other';

export interface ListNodesParams {
  env: string;
  status?: NodeStatus;
  q?: string;
  sort?: NodeSort;
  dir?: SortDir;
  page?: number;
  pageSize?: number;
  /** Narrow to one platform bucket. Empty / omitted means "all". */
  platform?: NodePlatform;
}

export function listNodes(p: ListNodesParams): Promise<NodesPagedResponse> {
  const params = new URLSearchParams();
  if (p.status && p.status !== 'all') params.set('status', p.status);
  if (p.q) params.set('q', p.q);
  if (p.sort) params.set('sort', p.sort);
  if (p.dir) params.set('dir', p.dir);
  if (p.page != null) params.set('page', String(p.page));
  if (p.pageSize != null) params.set('page_size', String(p.pageSize));
  if (p.platform) params.set('platform', p.platform);

  const qs = params.toString();
  return apiFetch<NodesPagedResponse>(
    `/api/v1/nodes/${encodeURIComponent(p.env)}${qs ? `?${qs}` : ''}`,
  );
}

export function getNode(env: string, uuid: string): Promise<OsqueryNode> {
  return apiFetch<OsqueryNode>(
    `/api/v1/nodes/${encodeURIComponent(env)}/node/${encodeURIComponent(uuid)}`,
  );
}

export function listNodeLogs(
  env: string,
  uuid: string,
  type: 'status' | 'result',
  limit?: number,
  since?: string,
  q?: string,
): Promise<NodeLogsResponse> {
  const params = new URLSearchParams();
  if (limit != null) params.set('limit', String(limit));
  if (since) params.set('since', since);
  // Free-text search (substring, case-insensitive) — server-side LIKE
  // against the human-readable columns: status rows match against
  // line/message/filename; result rows match against name/action/columns.
  // Empty string is treated as "no filter" by the API.
  if (q && q.trim()) params.set('q', q.trim());

  const qs = params.toString();
  return apiFetch<NodeLogsResponse>(
    `/api/v1/logs/${encodeURIComponent(type)}/${encodeURIComponent(env)}/${encodeURIComponent(uuid)}${qs ? `?${qs}` : ''}`,
  );
}
