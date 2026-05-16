import { apiFetch } from './client';

/**
 * Per-platform node counts. Drives the Nodes-table QuickFilters chip row
 * ([Linux N] [macOS N] [Windows N] [Other N]). Mirrors pkg/nodes.PlatformCounts
 * on the Go side. Counts are total — both active and inactive — since the
 * platform filter is independent of the active/inactive filter.
 */
export interface PlatformCounts {
  linux: number;
  darwin: number;
  windows: number;
  other: number;
}

export interface EnvStats {
  uuid: string;
  name: string;
  active: number;
  inactive: number;
  total: number;
  active_queries: number;
  active_carves: number;
  /** Per-env breakdown by OS family. */
  platform_counts: PlatformCounts;
}

export interface StatsResponse {
  total_nodes: number;
  active_nodes: number;
  inactive_nodes: number;
  total_active_queries: number;
  total_active_carves: number;
  /** Cross-env aggregate (sum of every env.platform_counts the user can see). */
  platform_counts: PlatformCounts;
  environments: EnvStats[];
}

export function getStats(): Promise<StatsResponse> {
  return apiFetch<StatsResponse>('/api/v1/stats');
}

/**
 * Fleet-wide osquery agent version breakdown. Powers the dashboard's "agent
 * fleet hygiene" panel — operators use it to spot stale agents that need
 * upgrading. Sorted by count descending (most-common version first).
 *
 * Mirrors pkg/nodes.OsqueryVersionCount on the Go side.
 */
export interface OsqueryVersionCount {
  version: string;
  count: number;
}

export function getOsqueryVersionCounts(): Promise<OsqueryVersionCount[]> {
  return apiFetch<OsqueryVersionCount[]>('/api/v1/stats/osquery-versions');
}

/**
 * One cell of the per-env activity heatmap. Bucket size varies by `interval`
 * — the Go side picks a bucketSeconds that keeps the cell count in the 36..96
 * range across the full picker. The 4 counters partition audit-log entries
 * by their log_type → category mapping (see EnvActivityHandler):
 *   - config ← Setting (8) + Environment (7)
 *   - query  ← Query (4)
 *   - carve  ← Carve (5)
 *   - enroll ← Node (3)
 *
 * Buckets are returned contiguously — empty windows ship zero rows for that
 * bucket — so the SPA grid renders without densifying client-side.
 */
export interface ActivityBucket {
  bucket_start: string;
  config: number;
  query: number;
  carve: number;
  enroll: number;
}

/**
 * Allowed activity-heatmap intervals. The Go side falls back to '1d' on any
 * unknown value, but typing it here keeps the picker honest.
 */
export type ActivityInterval = '3h' | '6h' | '12h' | '1d' | '2d' | '3d' | '7d';

export const ACTIVITY_INTERVALS: ActivityInterval[] = ['3h', '6h', '12h', '1d', '2d', '3d', '7d'];

export function getEnvActivity(env: string, interval: ActivityInterval = '1d'): Promise<ActivityBucket[]> {
  const sp = new URLSearchParams();
  sp.set('interval', interval);
  return apiFetch<ActivityBucket[]>(
    `/api/v1/stats/activity/${encodeURIComponent(env)}?${sp.toString()}`,
  );
}

/**
 * Per-node activity bucket. Categories pivot from the env-scoped variant —
 * what THIS device has been doing rather than what operators did to the env:
 *   - status ← osquery_status_data row count (status logs this node shipped)
 *   - result ← osquery_result_data row count (query results this node returned)
 *   - query  ← node_queries row count (distributed queries scheduled at this node)
 *   - carve  ← carved_files row count (carves this node produced)
 *
 * Same bucket-size-per-interval rules as the env variant.
 */
export interface NodeActivityBucket {
  bucket_start: string;
  status: number;
  result: number;
  query: number;
  carve: number;
}

export function getNodeActivity(
  env: string,
  uuid: string,
  interval: ActivityInterval = '1d',
): Promise<NodeActivityBucket[]> {
  const sp = new URLSearchParams();
  sp.set('interval', interval);
  return apiFetch<NodeActivityBucket[]>(
    `/api/v1/stats/activity/node/${encodeURIComponent(env)}/${encodeURIComponent(uuid)}?${sp.toString()}`,
  );
}

/**
 * Batch variant — fetches activity buckets for up to 100 nodes in one call.
 * Used by the Nodes table to render a sparkline column. Unknown / unauthorized
 * UUIDs are silently omitted from the response (the server treats one bad
 * UUID as no-data, not an error). Caller should treat a missing key as
 * "no activity to render," not "fetch failed."
 */
export function getNodeActivityBatch(
  env: string,
  uuids: string[],
  interval: ActivityInterval = '1d',
): Promise<Record<string, NodeActivityBucket[]>> {
  if (uuids.length === 0) {
    return Promise.resolve({});
  }
  const sp = new URLSearchParams();
  sp.set('interval', interval);
  sp.set('uuids', uuids.join(','));
  return apiFetch<Record<string, NodeActivityBucket[]>>(
    `/api/v1/stats/activity/node-batch/${encodeURIComponent(env)}?${sp.toString()}`,
  );
}
