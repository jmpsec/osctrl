/**
 * Log sinks API client.
 *
 * Access to the log_sinks table, which stores per-environment osquery
 * log destinations (Splunk, Kafka, S3, DB, stdout, …) as JSON-encoded
 * rows. Read endpoints redact secret fields unless reveal=1 is passed.
 * Mutating endpoints accept the raw config object; a secret field set
 * to "***" is merged from the previously stored value by the server.
 */
import { apiFetch } from './client';
import type { ServiceCommand } from './service-config';

/** Wire shape matching handlers.logSinkDTO. */
export interface LogSink {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  environment_id: number;
  type: string;
  enabled: boolean;
  order: number;
  config: unknown;
  source: string;
  info: string;
  bytes_sent: number;
  exports_count: number;
}

/** One field in a sink type's config schema. Drives the dynamic form. */
export interface LogSinkFieldSpec {
  name: string;
  label: string;
  /** string | integer | boolean | select | password */
  type: string;
  required: boolean;
  secret: boolean;
  placeholder?: string;
  help?: string;
  options?: string[];
  default?: unknown;
}

/** One entry in the GET /api/v1/log-sinks/types registry response. */
export interface LogSinkTypeSpec {
  type: string;
  description: string;
  has_secret: boolean;
  secret_fields?: string[];
  /** Typed field schema the SPA renders as a dynamic form. Absent for
   * sink types with no config (none, stdout). */
  fields?: LogSinkFieldSpec[];
}

/** GET /api/v1/log-sinks?env={id}&reveal={0|1}. */
export function listLogSinks(opts?: {
  env?: number;
  reveal?: boolean;
}): Promise<LogSink[]> {
  const params = new URLSearchParams();
  if (opts?.env !== undefined) params.set('env', String(opts.env));
  if (opts?.reveal) params.set('reveal', '1');
  const qs = params.toString();
  return apiFetch<LogSink[]>(`/api/v1/log-sinks${qs ? `?${qs}` : ''}`);
}

/** GET /api/v1/log-sinks/types. */
export function listLogSinkTypes(): Promise<LogSinkTypeSpec[]> {
  return apiFetch<LogSinkTypeSpec[]>('/api/v1/log-sinks/types');
}

/** GET /api/v1/log-sinks/{id}?reveal={0|1}. */
export function getLogSink(id: number, reveal?: boolean): Promise<LogSink> {
  const qs = reveal ? '?reveal=1' : '';
  return apiFetch<LogSink>(`/api/v1/log-sinks/${id}${qs}`);
}

/** Body for POST /api/v1/log-sinks. */
export interface LogSinkCreateRequest {
  name: string;
  type: string;
  enabled: boolean;
  order: number;
  config: unknown;
  environment_id: number;
  info?: string;
}

/** POST /api/v1/log-sinks. */
export function createLogSink(body: LogSinkCreateRequest): Promise<LogSink> {
  return apiFetch<LogSink>('/api/v1/log-sinks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** Body for PUT /api/v1/log-sinks/{id}. */
export interface LogSinkUpdateRequest {
  name: string;
  type: string;
  enabled: boolean;
  order: number;
  config: unknown;
  info?: string;
}

/** PUT /api/v1/log-sinks/{id}. */
export function updateLogSink(
  id: number,
  body: LogSinkUpdateRequest,
): Promise<LogSink> {
  return apiFetch<LogSink>(`/api/v1/log-sinks/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** DELETE /api/v1/log-sinks/{id}. Returns 204 No Content. */
export function deleteLogSink(id: number): Promise<void> {
  return apiFetch<void>(`/api/v1/log-sinks/${id}`, { method: 'DELETE' });
}

/** POST /api/v1/log-sinks/{id}/revert — flip source back to "service" so the next reload re-syncs from the service config. */
export function revertLogSink(id: number): Promise<LogSink> {
  return apiFetch<LogSink>(`/api/v1/log-sinks/${id}/revert`, { method: 'POST' });
}

/** Body for POST /api/v1/log-sinks/clone. */
export interface LogSinkCloneRequest {
  source_environment_id: number;
  target_environment_id: number;
  overwrite: boolean;
}

/** POST /api/v1/log-sinks/clone. */
export function cloneLogSinks(body: LogSinkCloneRequest): Promise<LogSink[]> {
  return apiFetch<LogSink[]>('/api/v1/log-sinks/clone', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** POST /api/v1/log-sinks/apply — queue a hot-reload of osctrl-tls sinks. */
export function applyLogSinks(): Promise<{
  message: string;
  service?: string;
  command?: ServiceCommand;
}> {
  return apiFetch('/api/v1/log-sinks/apply', { method: 'POST' });
}
