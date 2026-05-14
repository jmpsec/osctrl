/**
 * Audit log API client.
 */
import { apiFetch } from './client';

export interface AuditLogView {
  id: number;
  created_at: string;
  service: string;
  username: string;
  line: string;
  log_type: number;
  severity: number;
  source_ip: string;
  environment_id: number;
  env_uuid?: string;
}

export interface AuditLogsPagedResponse {
  items: AuditLogView[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface AuditLogsQuery {
  service?: string;
  username?: string;
  type?: number;
  env_uuid?: string;
  since?: string;
  until?: string;
  page?: number;
  page_size?: number;
}

export function listAuditLogs(q: AuditLogsQuery = {}): Promise<AuditLogsPagedResponse> {
  const sp = new URLSearchParams();
  if (q.service) sp.set('service', q.service);
  if (q.username) sp.set('username', q.username);
  if (q.type !== undefined) sp.set('type', String(q.type));
  if (q.env_uuid) sp.set('env_uuid', q.env_uuid);
  if (q.since) sp.set('since', q.since);
  if (q.until) sp.set('until', q.until);
  if (q.page) sp.set('page', String(q.page));
  if (q.page_size) sp.set('page_size', String(q.page_size));
  const query = sp.toString();
  return apiFetch<AuditLogsPagedResponse>(`/api/v1/audit-logs${query ? '?' + query : ''}`);
}

// Mirror pkg/auditlog log type constants.
export const LOG_TYPE = {
  Login: 1,
  Logout: 2,
  Node: 3,
  Query: 4,
  Carve: 5,
  Tag: 6,
  Environment: 7,
  Setting: 8,
  Visit: 9,
  User: 10,
} as const;

export const LOG_TYPE_LABELS: Record<number, string> = {
  1: 'login',
  2: 'logout',
  3: 'node',
  4: 'query',
  5: 'carve',
  6: 'tag',
  7: 'environment',
  8: 'setting',
  9: 'visit',
  10: 'user',
};
