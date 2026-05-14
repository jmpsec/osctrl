import { apiFetch } from './client';
import type {
  DistributedQuery,
  QueriesPagedResponse,
  QueryResultsResponse,
  QueryTarget,
  QuerySortColumn,
  SortDir,
} from './types';

export interface ListQueriesParams {
  env: string;
  target: QueryTarget;
  q?: string;
  sort?: QuerySortColumn;
  dir?: SortDir;
  page?: number;
  pageSize?: number;
}

/** GET /api/v1/queries/{env}/list/{target} — paginated */
export function listQueries(p: ListQueriesParams): Promise<QueriesPagedResponse> {
  const params = new URLSearchParams();
  if (p.q) params.set('q', p.q);
  if (p.sort) params.set('sort', p.sort);
  if (p.dir) params.set('dir', p.dir);
  if (p.page != null) params.set('page', String(p.page));
  if (p.pageSize != null) params.set('page_size', String(p.pageSize));

  const qs = params.toString();
  return apiFetch<QueriesPagedResponse>(
    `/api/v1/queries/${encodeURIComponent(p.env)}/list/${encodeURIComponent(p.target)}${qs ? `?${qs}` : ''}`,
  );
}

/** GET /api/v1/queries/{env}/{name} */
export function getQuery(env: string, name: string): Promise<DistributedQuery> {
  return apiFetch<DistributedQuery>(
    `/api/v1/queries/${encodeURIComponent(env)}/${encodeURIComponent(name)}`,
  );
}

export interface ListQueryResultsParams {
  env: string;
  name: string;
  page?: number;
  pageSize?: number;
  /** RFC3339 timestamp; only rows created strictly after this are returned. */
  since?: string;
}

/** GET /api/v1/queries/{env}/results/{name} — paginated + since-aware */
export function listQueryResults(p: ListQueryResultsParams): Promise<QueryResultsResponse> {
  const params = new URLSearchParams();
  if (p.page != null) params.set('page', String(p.page));
  if (p.pageSize != null) params.set('page_size', String(p.pageSize));
  if (p.since) params.set('since', p.since);
  const qs = params.toString();
  return apiFetch<QueryResultsResponse>(
    `/api/v1/queries/${encodeURIComponent(p.env)}/results/${encodeURIComponent(p.name)}${qs ? `?${qs}` : ''}`,
  );
}

export interface RunQueryBody {
  query: string;
  uuid_list?: string[];
  platform_list?: string[];
  environment_list?: string[];
  host_list?: string[];
  tag_list?: string[];
  hidden?: boolean;
  exp_hours?: number;
}

export interface RunQueryResponse {
  query_name: string;
}

/** POST /api/v1/queries/{env} */
export function runQuery(env: string, body: RunQueryBody): Promise<RunQueryResponse> {
  return apiFetch<RunQueryResponse>(
    `/api/v1/queries/${encodeURIComponent(env)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

export type QueryAction = 'delete' | 'expire' | 'complete';

/** POST /api/v1/queries/{env}/{action}/{name} */
export function actOnQuery(
  env: string,
  name: string,
  action: QueryAction,
): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/queries/${encodeURIComponent(env)}/${encodeURIComponent(action)}/${encodeURIComponent(name)}`,
    { method: 'POST' },
  );
}

/**
 * Returns the URL for the CSV download link.
 * Use directly as <a href> — the browser handles the file download.
 */
export function getQueryResultsCSVUrl(env: string, name: string): string {
  return `/api/v1/queries/${encodeURIComponent(env)}/results/csv/${encodeURIComponent(name)}`;
}
