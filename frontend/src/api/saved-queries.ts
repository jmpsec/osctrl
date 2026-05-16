import { apiFetch } from './client';
import type {
  SavedQuery,
  SavedQueriesPagedResponse,
  SavedQuerySortColumn,
  SortDir,
} from './types';

export interface ListSavedQueriesParams {
  env: string;
  q?: string;
  sort?: SavedQuerySortColumn;
  dir?: SortDir;
  page?: number;
  pageSize?: number;
}

/** GET /api/v1/saved-queries/{env} — paginated */
export function listSavedQueries(p: ListSavedQueriesParams): Promise<SavedQueriesPagedResponse> {
  const params = new URLSearchParams();
  if (p.q) params.set('q', p.q);
  if (p.sort) params.set('sort', p.sort);
  if (p.dir) params.set('dir', p.dir);
  if (p.page != null) params.set('page', String(p.page));
  if (p.pageSize != null) params.set('page_size', String(p.pageSize));

  const qs = params.toString();
  return apiFetch<SavedQueriesPagedResponse>(
    `/api/v1/saved-queries/${encodeURIComponent(p.env)}${qs ? `?${qs}` : ''}`,
  );
}

export interface CreateSavedQueryBody {
  name: string;
  query: string;
}

/** POST /api/v1/saved-queries/{env} */
export function createSavedQuery(env: string, body: CreateSavedQueryBody): Promise<SavedQuery> {
  return apiFetch<SavedQuery>(
    `/api/v1/saved-queries/${encodeURIComponent(env)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

export interface UpdateSavedQueryBody {
  query: string;
}

/** PATCH /api/v1/saved-queries/{env}/{name} */
export function updateSavedQuery(env: string, name: string, body: UpdateSavedQueryBody): Promise<SavedQuery> {
  return apiFetch<SavedQuery>(
    `/api/v1/saved-queries/${encodeURIComponent(env)}/${encodeURIComponent(name)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/** DELETE /api/v1/saved-queries/{env}/{name} */
export function deleteSavedQuery(env: string, name: string): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/saved-queries/${encodeURIComponent(env)}/${encodeURIComponent(name)}`,
    { method: 'DELETE' },
  );
}
