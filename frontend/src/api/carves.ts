import { apiFetch } from './client';
import type {
  CarvesPagedResponse,
  CarveDetail,
  CarveTarget,
  CarveSortColumn,
  SortDir,
} from './types';

export interface ListCarvesParams {
  env: string;
  target?: CarveTarget;
  q?: string;
  sort?: CarveSortColumn;
  dir?: SortDir;
  page?: number;
  pageSize?: number;
}

/** GET /api/v1/carves/{env} — paginated list of carve queries (type=carve). */
export function listCarves(p: ListCarvesParams): Promise<CarvesPagedResponse> {
  const params = new URLSearchParams();
  if (p.target) params.set('target', p.target);
  if (p.q) params.set('q', p.q);
  if (p.sort) params.set('sort', p.sort);
  if (p.dir) params.set('dir', p.dir);
  if (p.page != null) params.set('page', String(p.page));
  if (p.pageSize != null) params.set('page_size', String(p.pageSize));

  const qs = params.toString();
  return apiFetch<CarvesPagedResponse>(
    `/api/v1/carves/${encodeURIComponent(p.env)}${qs ? `?${qs}` : ''}`,
  );
}

/** GET /api/v1/carves/{env}/{name} — carve query + per-node carved files. */
export function getCarve(env: string, name: string): Promise<CarveDetail> {
  return apiFetch<CarveDetail>(
    `/api/v1/carves/${encodeURIComponent(env)}/${encodeURIComponent(name)}`,
  );
}

export interface RunCarveBody {
  path: string;
  uuid_list?: string[];
  platform_list?: string[];
  environment_list?: string[];
  host_list?: string[];
  tag_list?: string[];
  exp_hours?: number;
}

/**
 * Shape returned by POST /api/v1/carves/{env}.
 * The Go side serializes types.ApiQueriesResponse, which has the json tag
 * `query_name` (it's a shared struct between query-run and carve-run). The
 * SPA used to expect `name` and silently navigated to /carves/undefined
 * when the carve was actually created — the resulting "carve not found"
 * page made it look like a backend bug. This field is now keyed correctly.
 */
export interface RunCarveResponse {
  query_name: string;
}

/** POST /api/v1/carves/{env} — initiate a new file carve. */
export function runCarve(env: string, body: RunCarveBody): Promise<RunCarveResponse> {
  return apiFetch<RunCarveResponse>(
    `/api/v1/carves/${encodeURIComponent(env)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

export type CarveAction = 'delete' | 'expire' | 'complete';

/** POST /api/v1/carves/{env}/{action}/{name} */
export function actOnCarve(
  env: string,
  name: string,
  action: CarveAction,
): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/carves/${encodeURIComponent(env)}/${encodeURIComponent(action)}/${encodeURIComponent(name)}`,
    { method: 'POST' },
  );
}

/**
 * Returns the URL for downloading the reassembled archive of a carve.
 * Use directly as <a href> — the browser handles the file download.
 *
 * If the carve query produced files for multiple nodes, pass `session` to
 * disambiguate; omitted it expects exactly one file and returns 409 otherwise.
 */
export function getCarveArchiveUrl(env: string, name: string, session?: string): string {
  const params = new URLSearchParams();
  if (session) params.set('session', session);
  const qs = params.toString();
  return `/api/v1/carves/${encodeURIComponent(env)}/archive/${encodeURIComponent(name)}${qs ? `?${qs}` : ''}`;
}
