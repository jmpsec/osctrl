import { useState } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation } from '@tanstack/react-query';
import { listNodes, deleteNode, type NodePlatform } from '$/api/nodes';
import { getStats, getNodeActivityTilesBatch, type NodeTileSeries } from '$/api/stats';
import { listEnvTags, tagNode } from '$/api/tags';
import { getMe } from '$/api/users';
import { listEnvironments } from '$/api/environments';
import { AuthError } from '$/api/client';
import type { NodeSort, SortDir, NodeStatus, NodesPagedResponse, AdminTag } from '$/api/types';
import { formatRelative, formatBytes } from '$/lib/time';
import { isNodeActive, useInactiveHours } from '$/lib/node-status';
import { cn } from '$/lib/cn';
import { StatusBadge } from '$/components/data/StatusBadge';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SearchInput } from '$/components/data/SearchInput';
import { SortableHeader } from '$/components/data/SortableHeader';
import { ModalShell } from '$/components/feedback/ModalShell';

const TAG_TYPE_REGULAR = 6; // mirrors pkg/tags.TagTypeTag
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;

// ---------------------------------------------------------------------------
// Platform display helpers
// ---------------------------------------------------------------------------
const PLATFORM_LABEL: Record<NodePlatform, string> = {
  linux: 'Linux',
  darwin: 'macOS',
  windows: 'Windows',
  other: 'Other',
};

/** Maps node.platform (free string) → bucket key used by stats.platform_counts. */
function platformBucket(p: string): NodePlatform {
  const v = (p || '').toLowerCase();
  if (v === 'linux' || v === 'ubuntu' || v === 'debian' || v === 'centos' || v === 'rhel' || v === 'fedora' || v === 'arch') return 'linux';
  if (v === 'darwin' || v === 'macos' || v === 'osx') return 'darwin';
  if (v === 'windows' || v === 'win32' || v === 'win64') return 'windows';
  return 'other';
}

function PlatformIcon({ bucket, className }: { bucket: NodePlatform; className?: string }) {
  // Hand-drawn simple glyphs; one path each so the SVG stays trivially small.
  const cls = cn('w-3.5 h-3.5 flex-shrink-0', className);
  if (bucket === 'linux') {
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={cls} aria-hidden>
        <path d="M12 2c-2.5 0-3.5 2-3.5 4.5 0 1.5.6 2.7 1.5 3.5-1.4 1.3-2.5 3-2.5 5 0 3 2 4.5 2 6 0 .5-.4 1-1 1h-1c-.3 0-.5.2-.5.5s.2.5.5.5h11c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-1c-.6 0-1-.5-1-1 0-1.5 2-3 2-6 0-2-1.1-3.7-2.5-5 .9-.8 1.5-2 1.5-3.5C15.5 4 14.5 2 12 2zm-1.5 4c.5 0 1 .4 1 1s-.5 1-1 1-1-.4-1-1 .5-1 1-1zm3 0c.5 0 1 .4 1 1s-.5 1-1 1-1-.4-1-1 .5-1 1-1z" />
      </svg>
    );
  }
  if (bucket === 'darwin') {
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={cls} aria-hidden>
        <path d="M17.05 20.28c-.98.95-2.05.86-3.08.36-1.09-.5-2.08-.53-3.2 0-1.39.66-2.13.49-3.0-.36C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.79 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09M12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25" />
      </svg>
    );
  }
  if (bucket === 'windows') {
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={cls} aria-hidden>
        <path d="M3 5l8-1v8H3V5zm9-1.1l9-1.3v10.4h-9V3.9zM3 13h8v6.1l-8-1.1V13zm9 0h9v9.4l-9-1.3V13z" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={cls} aria-hidden>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v4M12 16h.01" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// QuickFilters chip row
// ---------------------------------------------------------------------------
interface QuickFilter {
  key: string;
  label: string;
  count: number | undefined;
  active: boolean;
  onClick: () => void;
}

function QuickFiltersGroup({ filters }: { filters: QuickFilter[] }) {
  // Same StatusTabs-style segmented pad as before, but without the
  // surrounding row chrome — meant to slot into the main toolbar
  // alongside the page title and search box so the whole header reads
  // as a single line (matches CarvesListPage layout).
  return (
    <div
      role="toolbar"
      aria-label="Quick filters"
      className="flex items-center gap-1 rounded-md bg-[color:var(--bg-2)] p-0.5 border border-[color:var(--border)]"
    >
      {filters.map((f) => (
        <button
          key={f.key}
          type="button"
          onClick={f.onClick}
          aria-pressed={f.active}
          aria-label={`Filter: ${f.label}${f.count != null ? ` (${f.count})` : ''}`}
          className={cn(
            'inline-flex items-center gap-1.5 px-3 py-1 rounded',
            'text-xs font-medium transition-colors',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            f.active
              ? 'bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-sm'
              : 'text-[color:var(--text-2)] hover:text-[color:var(--text-1)]',
          )}
        >
          <span>{f.label}</span>
          {f.count != null && (
            <span
              className={cn(
                'font-mono-tabular tabular-nums text-[10px]',
                f.active ? 'text-[color:var(--text-2)]' : 'text-[color:var(--text-3)]',
              )}
            >
              {f.count.toLocaleString()}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Compact compound cells
// ---------------------------------------------------------------------------
interface HostCellProps {
  env: string;
  uuid: string;
  hostname: string;
  localname: string;
  ip: string;
}

function HostCell({ env, uuid, hostname, localname, ip }: HostCellProps) {
  const displayName = hostname || localname || '—';
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <Link
        to="/_app/env/$env/nodes/$uuid"
        params={{ env, uuid }}
        className={cn(
          'text-[color:var(--text-link)] hover:underline truncate',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
          'rounded text-sm font-medium leading-tight',
        )}
      >
        {displayName}
      </Link>
      <div className="flex items-center gap-2 text-[10.5px] font-mono-tabular text-[color:var(--text-3)] leading-tight">
        <span title={uuid}>
          <span className="text-[color:var(--signal)]">{uuid.slice(0, 8)}</span>
          <span>…</span>
        </span>
        {ip && (
          <>
            <span aria-hidden className="opacity-50">·</span>
            <span title={`IP ${ip}`}>{ip}</span>
          </>
        )}
      </div>
    </div>
  );
}

interface SystemCellProps {
  platform: string;
  platformVersion: string;
  osqueryVersion: string;
}

function SystemCell({ platform, platformVersion, osqueryVersion }: SystemCellProps) {
  const bucket = platformBucket(platform);
  return (
    <div className="flex items-center gap-2 min-w-0">
      <PlatformIcon bucket={bucket} className="text-[color:var(--text-2)]" />
      <div className="flex flex-col gap-0.5 min-w-0 leading-tight">
        <span className="text-[12px] text-[color:var(--text-1)] truncate">
          <span className="text-[color:var(--text-2)]">{platform}</span>
          {platformVersion && (
            <span className="font-mono-tabular text-[10.5px] text-[color:var(--text-3)] ml-1.5">
              {platformVersion}
            </span>
          )}
        </span>
        {osqueryVersion && (
          <span className="font-mono-tabular text-[10.5px] text-[color:var(--text-3)] truncate">
            osquery {osqueryVersion}
          </span>
        )}
      </div>
    </div>
  );
}

interface ActivityCellProps {
  lastSeen: string;
  bytesReceived: number;
}

/**
 * Per-row "Activity" cell — last seen + bytes received. Just the textual
 * busy-signal; the 24h heatmap lives in its own column (HeatmapCell) so
 * each gets the width it needs.
 */
function ActivityCell({ lastSeen, bytesReceived }: ActivityCellProps) {
  return (
    <div className="flex flex-col gap-0.5 leading-tight">
      <span
        className="text-[12px] tabular-nums text-[color:var(--text-1)]"
        title={lastSeen}
      >
        {formatRelative(lastSeen)}
      </span>
      <span className="text-[10.5px] font-mono-tabular tabular-nums text-[color:var(--text-3)]">
        {formatBytes(bytesReceived)}
      </span>
    </div>
  );
}

interface HeatmapCellProps {
  /** Redis-backed per-node hourly tile series, or undefined while loading. */
  tiles?: NodeTileSeries;
  /** Global max per category across all visible nodes, for cross-node intensity. */
  globalMax?: Record<string, number>;
  /** The node's last_seen timestamp — used as a fallback signal when
   * Redis tiles are unavailable so the heatmap still reflects when this
   * specific node was last active. */
  lastSeen?: string;
}

/**
 * Per-row 5×24 mini activity heatmap from Redis-backed per-node tile data.
 *   - 5 rows of categories: status / result / config / query read / query write.
 *   - 24 columns, one per hour of the last 24h (left = oldest, right = now).
 *   - Intensity uses a global max across all visible nodes (passed via
 *     globalMax) so nodes with more activity show brighter than nodes with
 *     less. Without this, per-row normalization would make every node's
 *     busiest hour look identical.
 *
 * Per-cell tooltip shows the hour + 5-category breakdown.
 */
function HeatmapCell({ tiles, globalMax, lastSeen }: HeatmapCellProps) {
  // The Redis tile series has 24 hourly buckets for a 1-day window.
  // Trim future hours (the day blob is UTC-midnight aligned) so "now" is
  // the rightmost column.
  const trimToNow = (arr: number[] | undefined): number[] => {
    if (!arr || arr.length === 0) return new Array<number>(24).fill(0);
    const startMs = tiles ? Date.parse(tiles.start) : NaN;
    if (Number.isNaN(startMs)) return arr;
    const currentHourIdx = Math.floor((Date.now() - startMs) / 3_600_000);
    const cut = Math.max(1, Math.min(currentHourIdx + 1, arr.length));
    const trimmed = arr.slice(0, cut);
    // Right-pad to 24 so the grid doesn't shrink.
    while (trimmed.length < 24) trimmed.push(0);
    return trimmed;
  };

  // Check if Redis tiles have any data at all. If not, fall back to a
  // minimal signal from last_seen so each node's heatmap reflects when
  // IT was last active rather than showing an identical empty grid.
  const hasTilesData = tiles && tiles.total.some((v) => v > 0);

  let categoryHourly: number[][];
  if (hasTilesData) {
    categoryHourly = [
      trimToNow(tiles!.status.map((v) => v)),
      trimToNow(tiles!.result.map((v) => v)),
      trimToNow(tiles!.config.map((v) => v)),
      trimToNow(tiles!.query_read.map((v) => v)),
    ];
  } else {
    // Fallback: place a single config-row cell at the hour corresponding
    // to last_seen. Zero everywhere else. This makes the heatmap reflect
    // each node's actual last activity time.
    const empty = new Array<number>(24).fill(0);
    const config = new Array<number>(24).fill(0);
    const status = new Array<number>(24).fill(0);
    const result = new Array<number>(24).fill(0);
    const query = new Array<number>(24).fill(0);
    if (lastSeen) {
      const d = new Date(lastSeen);
      if (!isNaN(d.getTime())) {
        const now = new Date();
        const hoursAgo = Math.floor((now.getTime() - d.getTime()) / 3_600_000);
        if (hoursAgo >= 0 && hoursAgo < 24) {
          const idx = 23 - hoursAgo;
          config[idx] = 1;
          status[idx] = 1;
        }
      }
    }
    categoryHourly = [status, result, config, query];
  }

  const CATEGORIES = [
    { key: 'status', label: 'Status logs', baseVar: '--info' },
    { key: 'result', label: 'Result logs', baseVar: '--signal' },
    { key: 'config', label: 'Config fetches', baseVar: '--warning' },
    { key: 'query', label: 'Queries', baseVar: '--success' },
  ] as const;

  function tintForStep(baseVar: string, step: 0 | 1 | 2 | 3 | 4): string {
    if (step === 0) return 'var(--bg-3)';
    const pct = step === 1 ? 22 : step === 2 ? 45 : step === 3 ? 70 : 100;
    return `color-mix(in oklab, var(${baseVar}) ${pct}%, transparent)`;
  }

  function stepFor(v: number, max: number): 0 | 1 | 2 | 3 | 4 {
    if (v === 0 || max === 0) return 0;
    const scaled = Math.log10(v + 1) / Math.log10(max + 1);
    if (scaled < 0.25) return 1;
    if (scaled < 0.55) return 2;
    if (scaled < 0.85) return 3;
    return 4;
  }

  const totalEvents = categoryHourly.flat().reduce((a, b) => a + b, 0);

  // 7px cells + 2px gaps → 24*7 + 23*2 = 214px wide, 4*7 + 3*2 = 34px tall.
  // Fits in the dedicated 240px-wide column with room for px-4 padding (32px).
  return (
    <div
      className="inline-grid gap-[2px]"
      style={{ gridTemplateColumns: 'repeat(24, 7px)', gridTemplateRows: 'repeat(4, 7px)' }}
      role="img"
      aria-label={`Node activity over the last 24 hours, ${totalEvents} events total`}
      title="Node activity · last 24h"
    >
      {CATEGORIES.map((cat, catIdx) =>
        categoryHourly[catIdx].map((v, h) => {
          const step = stepFor(v, (globalMax?.[CATEGORIES[catIdx].key] ?? 0) || Math.max(...categoryHourly[catIdx], 0));
          const hoursAgo = 23 - h;
          const when =
            hoursAgo === 0 ? 'last hour' : hoursAgo === 1 ? '1 hour ago' : `${hoursAgo} hours ago`;
          const breakdown = CATEGORIES.map(
            (c, ci) => `${c.label}: ${categoryHourly[ci][h]}`,
          ).join(' · ');
          return (
            <span
              key={`${cat.key}-${h}`}
              className="rounded-[2px]"
              style={{ background: tintForStep(cat.baseVar, step) }}
              title={`${when}\n${breakdown}`}
            />
          );
        }),
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NodesTablePage
// ---------------------------------------------------------------------------

export function NodesTablePage() {
  usePageTitle('Nodes');
  const { env } = useParams({ from: '/_app/env/$env/nodes' });
  const search = useSearch({ from: '/_app/env/$env/nodes' });
  const navigate = useNavigate({ from: '/_app/env/$env/nodes' });
  const inactiveHours = useInactiveHours();

  const status: NodeStatus = search.status ?? 'all';
  const q: string = search.q ?? '';
  const sort: NodeSort = search.sort ?? 'lastseen';
  const dir: SortDir = search.dir ?? 'desc';
  const page: number = search.page ?? 1;
  const pageSize: number = search.page_size ?? 50;
  const platform: NodePlatform | undefined = search.platform;

  const [selectedUuids, setSelectedUuids] = useState<Set<string>>(new Set());
  const [tagModalOpen, setTagModalOpen] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);

  function updateSearch(patch: Record<string, string | number | undefined>) {
    void navigate({
      search: (prev: Record<string, unknown>) => {
        const next: Record<string, unknown> = { ...prev, ...patch };
        for (const key of Object.keys(next)) {
          if (next[key] === undefined) delete next[key];
        }
        return next as typeof prev;
      },
      replace: false,
    });
    setSelectedUuids(new Set());
  }

  // Server requires AdminLevel on the env for node deletion; mirror
  // that gate in the UI so non-admins don't see a button that 403s.
  // Super-admins always pass; env-scoped admins get it for their
  // env. Same logic used in NodeDetailPage's single-node delete.
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
  });
  const { data: envsForPerms } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
  });
  const envUuidForPerms = envsForPerms?.find((e) => e.name === env)?.uuid;
  const canDeleteNodes =
    me?.admin === true ||
    (envUuidForPerms !== undefined &&
      me?.permissions?.[envUuidForPerms]?.admin === true);

  const queryKey = ['nodes', env, { status, q, sort, dir, page, pageSize, platform }] as const;

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () =>
      listNodes({
        env,
        status,
        q: q || undefined,
        sort,
        dir,
        page,
        pageSize,
        platform,
      }),
    staleTime: 30_000,
    refetchInterval: 30_000,
    placeholderData: (prev: NodesPagedResponse | undefined) => prev,
  });

  // Bulk archive + delete the selected nodes. Backend exposes one
  // per-uuid endpoint (POST /nodes/{env}/delete) which is also the
  // legacy admin's archive-and-remove op. We fire one request per
  // uuid and collect per-row failures so a partial success can still
  // surface "deleted 7, failed 2" rather than the whole batch
  // turning red on the first 404.
  const bulkArchiveMut = useMutation({
    mutationFn: async (uuids: string[]) => {
      const settled = await Promise.allSettled(
        uuids.map((uuid) => deleteNode(env, uuid)),
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;
      return { total: uuids.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      setSelectedUuids(new Set());
      if (failed > 0) {
        setBulkError(`Archived ${total - failed} of ${total} node(s); ${failed} failed.`);
      } else {
        setBulkError(null);
      }
      void refetch();
    },
    onError: (err) =>
      setBulkError(err instanceof Error ? err.message : 'Bulk archive failed'),
  });

  function handleBulkArchive() {
    const uuids = Array.from(selectedUuids);
    if (uuids.length === 0) return;
    if (!confirm(`Archive ${uuids.length} node${uuids.length === 1 ? '' : 's'}?\n\nEach node is snapshotted into the archive table and removed from the active list. Forensic records are retained.`)) {
      return;
    }
    setBulkError(null);
    bulkArchiveMut.mutate(uuids);
  }

  // Stats — drives the QuickFilters chip counts. Cross-env totals; we surface
  // the per-env subset from data?.total_items when active.
  const { data: statsData } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    staleTime: 30_000,
    refetchInterval: 30_000,
  });

  // Per-row Redis-backed activity tiles. One batched HTTP call per visible
  // page — the server does a single Redis pipeline for all nodes. Each
  // row gets its own NodeTileSeries so the heatmap reflects that specific
  // node's activity, not an env-level aggregate.
  const visibleUuids = (data?.items ?? []).map((n) => n.uuid);
  const { data: tilesByUuid } = useQuery({
    queryKey: ['node-tiles-batch', env, visibleUuids] as const,
    queryFn: () => getNodeActivityTilesBatch(env, visibleUuids, 1),
    staleTime: 30_000,
    refetchInterval: 30_000,
    enabled: visibleUuids.length > 0,
  });

  // Compute a global max across all visible nodes (per category) so that
  // nodes with more activity show higher intensity than nodes with less.
  // Without this, per-row normalization makes every node's busiest hour
  // look identical (all step-4) even when the counts differ 10x.
  const globalMax = (() => {
    const max: Record<string, number> = { status: 0, result: 0, config: 0, query: 0 };
    for (const tiles of Object.values(tilesByUuid ?? {})) {
      if (!tiles.total?.some((v) => v > 0)) continue;
      for (const v of tiles.status ?? []) { if (v > max.status) max.status = v; }
      for (const v of tiles.result ?? []) { if (v > max.result) max.result = v; }
      for (const v of tiles.config ?? []) { if (v > max.config) max.config = v; }
      for (const v of tiles.query_read ?? []) { if (v > max.query) max.query = v; }
    }
    return max;
  })();

  // Pick out the current env's stat row for chip counts (active/inactive/total
  // + per-platform). Falls back to undefined while loading; chips render with
  // no count badge in that case.
  const envStat = statsData?.environments.find((e) => e.uuid === env);
  const platformCounts = envStat?.platform_counts;

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const nodes = data?.items ?? [];
  const totalItems = data?.total_items ?? 0;
  const totalPages = data?.total_pages ?? 0;

  function handleSortChange(col: NodeSort, newDir: SortDir) {
    updateSearch({ sort: col, dir: newDir, page: 1 });
  }

  // Multi-select
  const allVisible = nodes.map((n) => n.uuid);
  const allChecked = allVisible.length > 0 && allVisible.every((uuid) => selectedUuids.has(uuid));
  const someChecked = allVisible.some((uuid) => selectedUuids.has(uuid));

  function toggleAll() {
    if (allChecked) setSelectedUuids(new Set());
    else setSelectedUuids(new Set(allVisible));
  }

  function toggleRow(uuid: string) {
    setSelectedUuids((prev) => {
      const next = new Set(prev);
      if (next.has(uuid)) next.delete(uuid);
      else next.add(uuid);
      return next;
    });
  }

  // ---------------------------------------------------------------------------
  // QuickFilters config
  //
  // - "All N", "Active N", "Inactive N" — flip the status param, clear platform.
  // - "Linux N", "Windows N", "macOS N", "Other N" — set the platform param,
  //   keep the status param (so platform + active can compound).
  // ---------------------------------------------------------------------------
  const quickFilters: QuickFilter[] = [
    {
      key: 'all',
      label: 'All',
      count: envStat?.total,
      active: status === 'all' && !platform,
      onClick: () => updateSearch({ status: undefined, platform: undefined, page: 1 }),
    },
    {
      key: 'active',
      label: 'Active',
      count: envStat?.active,
      active: status === 'active' && !platform,
      onClick: () => updateSearch({ status: 'active', platform: undefined, page: 1 }),
    },
    {
      key: 'inactive',
      label: 'Inactive',
      count: envStat?.inactive,
      active: status === 'inactive' && !platform,
      onClick: () => updateSearch({ status: 'inactive', platform: undefined, page: 1 }),
    },
    {
      key: 'linux',
      label: 'Linux',
      count: platformCounts?.linux,
      active: platform === 'linux',
      onClick: () => updateSearch({ platform: 'linux', page: 1 }),
    },
    {
      key: 'darwin',
      label: 'macOS',
      count: platformCounts?.darwin,
      active: platform === 'darwin',
      onClick: () => updateSearch({ platform: 'darwin', page: 1 }),
    },
    {
      key: 'windows',
      label: 'Windows',
      count: platformCounts?.windows,
      active: platform === 'windows',
      onClick: () => updateSearch({ platform: 'windows', page: 1 }),
    },
    {
      key: 'other',
      label: 'Other',
      count: platformCounts?.other,
      active: platform === 'other',
      onClick: () => updateSearch({ platform: 'other', page: 1 }),
    },
  ];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Toolbar — single line matching CarvesListPage:
              [Title] [Status+platform chip pad] [Search] [Page size] [Refreshing…]
          Previously the chip pad lived in its own row above the search
          bar; folding both into one toolbar trims a row of vertical
          chrome and matches the env's other list pages. ── */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Nodes
        </h1>

        <QuickFiltersGroup filters={quickFilters} />

        <div className="flex-1 max-w-xs">
          <SearchInput
            value={q}
            onChange={(v) => updateSearch({ q: v || undefined, page: 1 })}
            placeholder="Search nodes…"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <label htmlFor="page-size" className="sr-only">Rows per page</label>
          <select
            id="page-size"
            value={pageSize}
            onChange={(e) => updateSearch({ page_size: Number(e.target.value), page: 1 })}
            className={cn(
              'text-xs px-2 py-1.5 rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-2)]',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          >
            {PAGE_SIZE_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {n} / page
              </option>
            ))}
          </select>

          {isFetching && !isLoading && (
            <span
              aria-live="polite"
              aria-label="Refreshing data"
              className="text-[10px] text-[color:var(--text-3)] font-mono-tabular"
            >
              refreshing…
            </span>
          )}
        </div>
      </div>

      {/* ── Table ──
          table-fixed + explicit colgroup. The 24h heatmap gets its own
          240px column so it can use comfortable 7px cells without competing
          with the Activity (last-seen + bytes) column for space. Hostname
          is the flex column that absorbs leftover width. */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse table-fixed">
          <colgroup>
            <col className="w-10" />
            <col className="w-[110px]" />
            <col />
            <col className="w-[180px]" />
            <col className="w-[120px]" />
            <col className="w-[240px]" />
          </colgroup>
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-2.5">
                <input
                  type="checkbox"
                  aria-label="Select all visible nodes"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked && !allChecked;
                  }}
                  onChange={toggleAll}
                  className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                />
              </th>
              <th
                scope="col"
                className="px-4 py-2.5 text-left text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]"
              >
                Status
              </th>
              <SortableHeader
                column="hostname"
                label="Hostname"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              {/*
                We surface a single "UUID" header — invisible to the eye, but
                the test fixture references `getByText('abc12345')` and we want
                a discoverable name. The UUID short-hash is now inside HostCell;
                the test still locates it via getByText since textContent matches.
              */}
              <SortableHeader
                column="platform"
                label="System"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column="lastseen"
                label="Activity"
                currentSort={sort}
                currentDir={dir}
                defaultDir="desc"
                onSortChange={handleSortChange}
              />
              <th
                scope="col"
                className="px-4 py-2.5 text-left text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]"
              >
                24h
              </th>
            </tr>
          </thead>

          <tbody data-stale={isFetching && !isLoading ? 'true' : undefined}>
            {isLoading && Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}

            {isError && !isLoading && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={error instanceof Error ? error.message : 'Failed to load nodes'}
                    action={
                      <button
                        type="button"
                        onClick={() => void refetch()}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Retry
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading && !isError && nodes.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <rect x="3" y="4" width="18" height="16" rx="2" />
                        <path d="M3 10h18" />
                      </svg>
                    }
                    title="No nodes match."
                    action={
                      (q || status !== 'all' || platform) ? (
                        <button
                          type="button"
                          onClick={() =>
                            updateSearch({
                              q: undefined,
                              status: undefined,
                              platform: undefined,
                              page: 1,
                            })
                          }
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Clear filters
                        </button>
                      ) : null
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              nodes.map((node) => {
                const isActive = isNodeActive(node.last_seen, inactiveHours);
                const isSelected = selectedUuids.has(node.uuid);

                return (
                  <tr
                    key={node.uuid}
                    className={cn(
                      'border-b border-[color:var(--border)] transition-colors',
                      'hover:bg-[color:var(--bg-2)]',
                      isSelected && 'bg-[color:var(--bg-2)]',
                    )}
                  >
                    <td className="px-4 py-2.5 align-middle">
                      <input
                        type="checkbox"
                        aria-label={`Select node ${node.hostname}`}
                        checked={isSelected}
                        onChange={() => toggleRow(node.uuid)}
                        className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                      />
                    </td>

                    {/* Status — pip + label */}
                    <td className="px-4 py-2.5 align-middle">
                      <StatusBadge
                        variant={isActive ? 'success' : 'dim'}
                        label={isActive ? 'active' : 'inactive'}
                      />
                    </td>

                    {/* Host — name + uuid + ip stacked */}
                    <td className="px-4 py-2.5 align-middle">
                      <HostCell
                        env={env}
                        uuid={node.uuid}
                        hostname={node.hostname}
                        localname={node.localname}
                        ip={node.ip_address}
                      />
                    </td>

                    {/* System — platform icon + version + osquery */}
                    <td className="px-4 py-2.5 align-middle">
                      <SystemCell
                        platform={node.platform}
                        platformVersion={node.platform_version}
                        osqueryVersion={node.osquery_version}
                      />
                    </td>

                    {/* Activity — last seen + data received */}
                    <td className="px-4 py-2.5 align-middle">
                      <ActivityCell
                        lastSeen={node.last_seen}
                        bytesReceived={node.bytes_received}
                      />
                    </td>

                    {/* 24h — 4-category heatmap, dedicated column for breathing room */}
                    <td className="px-4 py-2.5 align-middle">
                      <HeatmapCell tiles={tilesByUuid?.[node.uuid]} globalMax={globalMax} lastSeen={node.last_seen} />
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {!isLoading && !isError && (
        <Pagination
          page={page}
          totalPages={totalPages}
          totalItems={totalItems}
          pageSize={pageSize}
          onPageChange={(p) => updateSearch({ page: p })}
        />
      )}

      {/* ── Multi-select dock toolbar ── */}
      {selectedUuids.size > 0 && (
        <div
          role="toolbar"
          aria-label="Bulk actions"
          className={cn(
            'fixed bottom-6 left-1/2 -translate-x-1/2',
            'flex items-center gap-3 px-4 py-2.5 rounded-xl',
            'bg-[color:var(--bg-1)] border border-[color:var(--border-strong)]',
            'shadow-[0_8px_32px_rgba(0,0,0,0.32)]',
            'text-sm font-medium',
            'z-50',
          )}
        >
          <span className="text-[color:var(--text-2)] text-xs font-mono-tabular">
            {selectedUuids.size} selected
          </span>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          <button
            type="button"
            aria-label="Tag selected nodes"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
            onClick={() => setTagModalOpen(true)}
          >
            Tag…
          </button>
          {canDeleteNodes && (
            <button
              type="button"
              aria-label="Archive selected nodes"
              disabled={bulkArchiveMut.isPending}
              className={cn(
                'px-3 py-1 text-xs font-medium rounded text-[color:var(--danger)]',
                'hover:bg-[color:var(--bg-2)] transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
              onClick={handleBulkArchive}
            >
              {bulkArchiveMut.isPending ? 'Archiving…' : 'Archive…'}
            </button>
          )}
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          <button
            type="button"
            aria-label="Clear selection"
            onClick={() => setSelectedUuids(new Set())}
            className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Clear
          </button>
        </div>
      )}

      {tagModalOpen && (
        <TagSelectedNodesModal
          env={env}
          uuids={Array.from(selectedUuids)}
          onClose={() => setTagModalOpen(false)}
          onTagged={() => {
            setTagModalOpen(false);
            setSelectedUuids(new Set());
            void refetch();
          }}
        />
      )}

      {/* Bulk-action result toast — sits at the bottom centre when no
          selection exists (so it doesn't overlap the dock toolbar). */}
      {bulkError && selectedUuids.size === 0 && (
        <div
          role="alert"
          className={cn(
            'fixed bottom-6 left-1/2 -translate-x-1/2 z-50',
            'flex items-center gap-3 px-4 py-2.5 rounded-xl',
            'bg-[color:var(--bg-1)] border border-[color:var(--danger)]/40',
            'shadow-[0_8px_32px_rgba(0,0,0,0.32)]',
            'text-xs text-[color:var(--danger)]',
          )}
        >
          <span>{bulkError}</span>
          <button
            type="button"
            onClick={() => setBulkError(null)}
            className="text-[color:var(--text-3)] hover:text-[color:var(--text-1)]"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tag-selected-nodes modal
// ---------------------------------------------------------------------------
function TagSelectedNodesModal({
  env,
  uuids,
  onClose,
  onTagged,
}: {
  env: string;
  uuids: string[];
  onClose: () => void;
  onTagged: () => void;
}) {
  const [chosen, setChosen] = useState<string>('');
  const [err, setErr] = useState<string | null>(null);

  const { data: tags, isLoading: tagsLoading } = useQuery({
    queryKey: ['tags', env],
    queryFn: () => listEnvTags(env),
    staleTime: 60_000,
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (!chosen) throw new Error('Pick a tag to assign.');
      if (uuids.length === 0) throw new Error('No nodes selected.');
      const results = await Promise.allSettled(
        uuids.map((uuid) => tagNode(env, { uuid, tag: chosen, type: TAG_TYPE_REGULAR })),
      );
      const failed = results
        .map((r, i) => ({ r, uuid: uuids[i] }))
        .filter(({ r }) => r.status === 'rejected')
        .map(({ uuid }) => uuid);
      if (failed.length > 0) {
        const shown = failed.slice(0, 3).join(', ');
        const extra = failed.length > 3 ? `, +${failed.length - 3} more` : '';
        throw new Error(`Failed on ${failed.length} node(s): ${shown}${extra}`);
      }
    },
    onSuccess: () => {
      onTagged();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Tagging failed');
    },
  });

  const list: AdminTag[] = tags ?? [];

  return (
    <ModalShell
      title={`Tag ${uuids.length} node${uuids.length === 1 ? '' : 's'}`}
      titleId="node-tag-modal-title"
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label htmlFor="node-tag-select" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Tag
          </label>
          <select
            id="node-tag-select"
            value={chosen}
            onChange={(e) => setChosen(e.target.value)}
            disabled={tagsLoading || list.length === 0}
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            <option value="">
              {tagsLoading
                ? 'Loading tags…'
                : list.length === 0
                  ? 'No tags in this environment'
                  : 'Pick a tag…'}
            </option>
            {list.map((t) => (
              <option key={t.id} value={t.name}>
                {t.name}
                {t.description ? ` — ${t.description}` : ''}
              </option>
            ))}
          </select>
          {!tagsLoading && list.length === 0 && (
            <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
              Create a tag from the Tags page first.
            </p>
          )}
        </div>

        {err && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {err}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending || !chosen || list.length === 0}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Tagging…' : 'Apply tag'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

export default NodesTablePage;
