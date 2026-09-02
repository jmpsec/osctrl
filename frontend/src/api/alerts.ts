/**
 * Alerts API client.
 *
 * Access to the alerting subsystem: rules (what to watch), channels
 * (where notifications go), recent history (what was sent), and the
 * apply command that hot-reloads osctrl-tls. Channel configs redact
 * secret fields unless reveal=1; an update submitting the "***"
 * placeholder preserves the stored secret server-side.
 */
import { apiFetch } from './client';
import type { ServiceCommand } from './service-config';

/** Wire shape matching handlers.alertRuleDTO. */
export interface AlertRule {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  environment_id: number;
  source: string;
  /** Scopes the rule to one node (set by the node detail "alert on this
   * node" flow). Empty = all nodes. */
  node_uuid: string;
  match_type: string;
  match_field: string;
  match_value: string;
  status_severity: string;
  cooldown_minutes: number;
  channel_ids: number[];
  enabled: boolean;
  info: string;
}

/** Wire shape matching handlers.alertChannelDTO. */
export interface AlertChannel {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  environment_id: number;
  type: string;
  enabled: boolean;
  config: unknown;
  info: string;
}

/** Wire shape matching alerts.AlertHistory. */
export interface AlertHistoryEntry {
  id: number;
  created_at: string;
  rule_id: number;
  rule_name: string;
  channel_id: number;
  channel_name: string;
  environment: string;
  node_uuid: string;
  entity: string;
  detail: string;
}

/** One field in a channel type's config schema. Drives the dynamic form. */
export interface AlertFieldSpec {
  name: string;
  label: string;
  /** string | integer | boolean | secret */
  type: string;
  required: boolean;
  placeholder?: string;
  help?: string;
  default?: unknown;
}

/** One entry in the GET /api/v1/alerts/channels/types registry response. */
export interface AlertChannelTypeSpec {
  type: string;
  description: string;
  has_secret: boolean;
  secret_fields?: string[];
  fields?: AlertFieldSpec[];
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export interface AlertRuleRequest {
  name: string;
  environment_id: number;
  source: string;
  node_uuid?: string;
  match_type: string;
  match_field?: string;
  match_value: string;
  status_severity?: string;
  cooldown_minutes?: number;
  channel_ids?: number[];
  enabled: boolean;
  info?: string;
}

/** GET /api/v1/alerts/rules?env={id}. */
export function listAlertRules(opts?: { env?: number }): Promise<AlertRule[]> {
  const params = new URLSearchParams();
  if (opts?.env !== undefined) params.set('env', String(opts.env));
  const qs = params.toString();
  return apiFetch<AlertRule[]>(`/api/v1/alerts/rules${qs ? `?${qs}` : ''}`);
}

/** POST /api/v1/alerts/rules. */
export function createAlertRule(body: AlertRuleRequest): Promise<AlertRule> {
  return apiFetch<AlertRule>('/api/v1/alerts/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** PUT /api/v1/alerts/rules/{id}. */
export function updateAlertRule(id: number, body: AlertRuleRequest): Promise<AlertRule> {
  return apiFetch<AlertRule>(`/api/v1/alerts/rules/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** DELETE /api/v1/alerts/rules/{id}. Returns 204 No Content. */
export function deleteAlertRule(id: number): Promise<void> {
  return apiFetch<void>(`/api/v1/alerts/rules/${id}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

export interface AlertChannelRequest {
  name: string;
  environment_id: number;
  type: string;
  enabled: boolean;
  config: unknown;
  info?: string;
}

/** GET /api/v1/alerts/channels?env={id}&reveal={0|1}. */
export function listAlertChannels(opts?: {
  env?: number;
  reveal?: boolean;
}): Promise<AlertChannel[]> {
  const params = new URLSearchParams();
  if (opts?.env !== undefined) params.set('env', String(opts.env));
  if (opts?.reveal) params.set('reveal', '1');
  const qs = params.toString();
  return apiFetch<AlertChannel[]>(`/api/v1/alerts/channels${qs ? `?${qs}` : ''}`);
}

/** GET /api/v1/alerts/channels/types. */
export function listAlertChannelTypes(): Promise<AlertChannelTypeSpec[]> {
  return apiFetch<AlertChannelTypeSpec[]>('/api/v1/alerts/channels/types');
}

/** POST /api/v1/alerts/channels. */
export function createAlertChannel(body: AlertChannelRequest): Promise<AlertChannel> {
  return apiFetch<AlertChannel>('/api/v1/alerts/channels', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** PUT /api/v1/alerts/channels/{id}. */
export function updateAlertChannel(id: number, body: AlertChannelRequest): Promise<AlertChannel> {
  return apiFetch<AlertChannel>(`/api/v1/alerts/channels/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** DELETE /api/v1/alerts/channels/{id}. Returns 204 No Content. */
export function deleteAlertChannel(id: number): Promise<void> {
  return apiFetch<void>(`/api/v1/alerts/channels/${id}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// History + apply
// ---------------------------------------------------------------------------

/** GET /api/v1/alerts/history?limit={n}. */
export function listAlertHistory(limit?: number): Promise<AlertHistoryEntry[]> {
  const qs = limit !== undefined ? `?limit=${limit}` : '';
  return apiFetch<AlertHistoryEntry[]>(`/api/v1/alerts/history${qs}`);
}

/** POST /api/v1/alerts/apply — queue a hot-reload of osctrl-tls rules and channels. */
export function applyAlerts(): Promise<{
  message: string;
  service?: string;
  command?: ServiceCommand;
}> {
  return apiFetch('/api/v1/alerts/apply', { method: 'POST' });
}
