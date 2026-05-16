import { apiFetch } from './client';
import type { OsqueryTable } from './types';

/** GET /api/v1/osquery/tables — loads once per session via staleTime: Infinity */
export function getOsqueryTables(): Promise<OsqueryTable[]> {
  return apiFetch<OsqueryTable[]>('/api/v1/osquery/tables');
}
