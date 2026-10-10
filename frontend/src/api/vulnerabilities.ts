/**
 * Vulnerability monitoring API client (--vuln-enabled).
 *
 * Every route answers 503 when the feature is off, and the environment
 * routes need the environment admin permission. The SPA only calls them
 * when features.vulnerabilities is true.
 */
import { apiFetch } from './client';
import type { PostureProfile } from './types';

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type VulnConfidence = 'confirmed' | 'possible';
export type VulnState = 'open' | 'resolved' | 'all';

export interface VulnFinding {
  id: number;
  node_uuid: string;
  environment_id: number;
  advisory_id: string;
  ecosystem: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  confidence: VulnConfidence;
  severity: VulnSeverity;
  kev: boolean;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
}

export interface VulnFindingsPage {
  findings: VulnFinding[];
  total: number;
  page: number;
}

export interface VulnCountRow {
  name: string;
  total: number;
}

export interface VulnSummary {
  /** False until the first OSV sync succeeds: zero findings then means "unknown". */
  loaded: boolean;
  /** True when a feed has not synced successfully for three sync intervals. */
  stale: boolean;
  by_severity: Partial<Record<VulnSeverity, Partial<Record<VulnConfidence, number>>>>;
  kev: number;
  affected_nodes: number;
  not_assessed: number;
  top_advisories: VulnCountRow[];
  top_packages: VulnCountRow[];
}

export interface VulnAdvisory {
  id: string;
  summary: string;
  details: string;
  cvss_vector: string;
  cvss_score: number;
  severity: VulnSeverity;
  kev: boolean;
  published: string;
  modified: string;
}

export interface VulnAdvisoryDetail {
  advisory: VulnAdvisory;
  aliases: string[];
  references: string[];
  /** Open findings for this advisory in the requested environment only. */
  findings: VulnFinding[];
}

export interface VulnNodeReport {
  findings: VulnFinding[];
  not_assessed: number;
  /** Null, or Go's zero time, when the node never reported inventory. */
  inventory_at: string | null;
  matched_at: string | null;
  loaded: boolean;
  stale: boolean;
}

export interface VulnSyncState {
  source: string;
  cursor: string;
  last_success: string | null;
  last_written: number;
  last_skipped: number;
  last_error: string;
  last_error_at: string | null;
}

export interface VulnFeedStatus {
  sources: VulnSyncState[];
  last_sync_at: string | null;
  sync_requested_at: string | null;
  last_sync_failed: boolean;
  loaded: boolean;
  stale: boolean;
}

export interface VulnFindingFilter {
  severity?: VulnSeverity;
  confidence?: VulnConfidence;
  kev?: boolean;
  state?: VulnState;
  package?: string;
  advisory?: string;
  page?: number;
  page_size?: number;
}

export const VULN_PAGE_SIZE = 50;

function envPath(env: string): string {
  return `/api/v1/vulnerabilities/${encodeURIComponent(env)}`;
}

/** GET /api/v1/vulnerabilities/{env}/findings — open findings unless state says otherwise. */
export function listVulnFindings(env: string, filter: VulnFindingFilter = {}): Promise<VulnFindingsPage> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value === undefined || value === '' || value === false) continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return apiFetch<VulnFindingsPage>(`${envPath(env)}/findings${qs ? `?${qs}` : ''}`);
}

/** GET /api/v1/vulnerabilities/{env}/summary */
export function getVulnSummary(env: string): Promise<VulnSummary> {
  return apiFetch<VulnSummary>(`${envPath(env)}/summary`);
}

/** GET /api/v1/vulnerabilities/{env}/advisories/{id} — 404 for an unknown id. */
export function getVulnAdvisory(env: string, id: string): Promise<VulnAdvisoryDetail> {
  return apiFetch<VulnAdvisoryDetail>(`${envPath(env)}/advisories/${encodeURIComponent(id)}`);
}

/** GET /api/v1/nodes/{env}/node/{uuid}/vulnerabilities */
export function getNodeVulns(env: string, uuid: string): Promise<VulnNodeReport> {
  return apiFetch<VulnNodeReport>(
    `/api/v1/nodes/${encodeURIComponent(env)}/node/${encodeURIComponent(uuid)}/vulnerabilities`,
  );
}

/** GET /api/v1/vulnerabilities/feeds — super admin only. */
export function getVulnFeeds(): Promise<VulnFeedStatus> {
  return apiFetch<VulnFeedStatus>('/api/v1/vulnerabilities/feeds');
}

/** POST /api/v1/vulnerabilities/feeds/sync — super admin only; the worker
 * starts the sync on its next tick. */
export function requestVulnSync(): Promise<{ message: string }> {
  return apiFetch<{ message: string }>('/api/v1/vulnerabilities/feeds/sync', { method: 'POST' });
}

/** GET /api/v1/vulnerabilities/profiles — same shape as posture profiles. */
export function getVulnProfiles(): Promise<PostureProfile[]> {
  return apiFetch<PostureProfile[]>('/api/v1/vulnerabilities/profiles');
}
