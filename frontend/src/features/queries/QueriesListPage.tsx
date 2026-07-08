import { useState } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation } from '@tanstack/react-query';
import { listQueries, actOnQuery } from '$/api/queries';
import { AuthError } from '$/api/client';
import type { QueryTarget, QuerySortColumn, SortDir, QueriesPagedResponse } from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { StatusTabs } from '$/components/data/StatusTabs';
import type { StatusTab } from '$/components/data/StatusTabs';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SearchInput } from '$/components/data/SearchInput';
import { SortableHeader } from '$/components/data/SortableHeader';

function QueryStatusBadge({
  q,
}: {
  q: { active: boolean; completed: boolean; expired: boolean; deleted: boolean };
}) {
  if (q.deleted) return <ListBadge variant="danger" label="Deleted" />;
  if (q.expired) return <ListBadge variant="warning" label="Expired" />;
  if (q.completed) return <ListBadge variant="success" label="Completed" />;
  if (q.active) return <ListBadge variant="info" label="Active" />;
  return <ListBadge variant="dim" label="Unknown" />;
}

function ListBadge({
  variant,
  label,
}: {
  variant: 'success' | 'warning' | 'danger' | 'info' | 'dim';
  label: string;
}) {
  const cls = {
    success:
      'bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.12)] text-[color:var(--success)]',
    warning:
      'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]',
    danger:
      'bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.12)] text-[color:var(--danger)]',
    info: 'bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.12)] text-[color:var(--info)]',
    dim: 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
  }[variant];

  return <span className={cn('px-2 py-0.5 rounded-full text-xs font-medium', cls)}>{label}</span>;
}

// ---------------------------------------------------------------------------
// Status tabs config
// ---------------------------------------------------------------------------
// Note: 'saved' is omitted intentionally — saved-query CRUD ships in //       The route enum still accepts it for forward-compat / deep-linking.
const QUERY_STATUS_TABS: StatusTab<QueryTarget>[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'completed', label: 'Completed' },
  { value: 'expired', label: 'Expired' },
  { value: 'deleted', label: 'Deleted' },
  { value: 'hidden', label: 'Hidden' },
];

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;

// ---------------------------------------------------------------------------
// QueriesListPage
// ---------------------------------------------------------------------------
export function QueriesListPage() {
  usePageTitle('Queries');
  const { env } = useParams({ from: '/_app/env/$env/queries' });
  const search = useSearch({ from: '/_app/env/$env/queries' });
  const navigate = useNavigate({ from: '/_app/env/$env/queries' });

  const target: QueryTarget = (search.target as QueryTarget) ?? 'all';
  const q: string = search.q ?? '';
  const sort: QuerySortColumn = (search.sort as QuerySortColumn) ?? 'created';
  const dir: SortDir = (search.dir as SortDir) ?? 'desc';
  const page: number = (search.page as number) ?? 1;
  const pageSize: number = (search.page_size as number) ?? 50;

  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
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
    setSelectedNames(new Set());
  }

  const queryKey = ['queries', env, { target, q, sort, dir, page, pageSize }] as const;

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () =>
      listQueries({
        env,
        target,
        q: q || undefined,
        sort,
        dir,
        page,
        pageSize,
      }),
    staleTime: 15_000,
    refetchInterval: 15_000,
    placeholderData: (prev: QueriesPagedResponse | undefined) => prev,
  });

  const bulkMutation = useMutation({
    mutationFn: async ({
      names,
      action,
    }: {
      names: string[];
      action: 'delete' | 'expire' | 'complete';
    }) => {
      const results = await Promise.allSettled(
        names.map((name) => actOnQuery(env, name, action)),
      );
      const failedNames = results
        .map((r, i) => ({ r, name: names[i] }))
        .filter(({ r }) => r.status === 'rejected')
        .map(({ name }) => name);
      if (failedNames.length > 0) {
        throw new Error(`${failedNames.length} action(s) failed: ${failedNames.join(', ')}`);
      }
    },
    onSuccess: () => {
      setSelectedNames(new Set());
      setBulkError(null);
      void refetch();
    },
    onError: (err) => {
      setBulkError(err instanceof Error ? err.message : 'Bulk action failed');
    },
  });

  // Redirect to login on 401
  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const items = data?.items ?? [];
  const totalItems = data?.total_items ?? 0;
  const totalPages = data?.total_pages ?? 0;

  // ---------------------------------------------------------------------------
  // Sort change
  // ---------------------------------------------------------------------------
  function handleSortChange(col: QuerySortColumn, newDir: SortDir) {
    updateSearch({ sort: col, dir: newDir, page: 1 });
  }

  // ---------------------------------------------------------------------------
  // Multi-select
  // ---------------------------------------------------------------------------
  const allVisible = items.map((q) => q.name);
  const allChecked =
    allVisible.length > 0 && allVisible.every((name) => selectedNames.has(name));
  const someChecked = allVisible.some((name) => selectedNames.has(name));

  function toggleAll() {
    if (allChecked) {
      setSelectedNames(new Set());
    } else {
      setSelectedNames(new Set(allVisible));
    }
  }

  function toggleRow(name: string) {
    setSelectedNames((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Toolbar ── */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        {/* Page title — matches the canonical Saves / Tags / etc. pattern so
            every env-scoped list page reads with the same brand voice. */}
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Queries
        </h1>

        {/* Status tabs */}
        <StatusTabs
          tabs={QUERY_STATUS_TABS}
          value={target}
          onChange={(v) => updateSearch({ target: v, page: 1 })}
        />

        {/* Search */}
        <div className="flex-1 max-w-xs">
          <SearchInput
            value={q}
            onChange={(v) => updateSearch({ q: v || undefined, page: 1 })}
            placeholder="Search queries…"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => void refetch()}
            disabled={isFetching}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'border border-[color:var(--border)] text-[color:var(--text-2)]',
              'hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
            aria-label="Refresh queries"
          >
            Refresh
          </button>

          {/* New query button */}
          <Link
            to="/_app/env/$env/queries/new"
            params={{ env }}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            Run query
          </Link>

          {/* Page size */}
          <label htmlFor="ql-page-size" className="sr-only">Rows per page</label>
          <select
            id="ql-page-size"
            value={pageSize}
            onChange={(e) => updateSearch({ page_size: Number(e.target.value), page: 1 })}
            className={cn(
              'text-xs px-2 py-1.5 rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-2)]',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          >
            {PAGE_SIZE_OPTIONS.map((n) => (
              <option key={n} value={n}>{n} / page</option>
            ))}
          </select>

          {/* Refreshing indicator */}
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

      {/* ── Table ── */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              {/* Select-all */}
              <th scope="col" className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  aria-label="Select all visible queries"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked && !allChecked;
                  }}
                  onChange={toggleAll}
                  className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                />
              </th>
              <SortableHeader
                column="name"
                label="Name"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column="creator"
                label="Creator"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <th
                scope="col"
                className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                Status
              </th>
              <th
                scope="col"
                className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                Type
              </th>
              <SortableHeader
                column="executions"
                label="Progress"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column="created"
                label="Created"
                currentSort={sort}
                currentDir={dir}
                defaultDir="desc"
                onSortChange={handleSortChange}
              />
            </tr>
          </thead>

          <tbody data-stale={isFetching && !isLoading ? 'true' : undefined}>
            {/* Loading skeleton */}
            {isLoading &&
              Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} cells={7} />)}

            {/* Error state */}
            {isError && !isLoading && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={error instanceof Error ? error.message : 'Failed to load queries'}
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

            {/* Empty state */}
            {!isLoading && !isError && items.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" />
                      </svg>
                    }
                    title="No queries match."
                    action={
                      (q || target !== 'all') ? (
                        <button
                          type="button"
                          onClick={() => updateSearch({ q: undefined, target: 'all', page: 1 })}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Clear filters
                        </button>
                      ) : (
                        <Link
                          to="/_app/env/$env/queries/new"
                          params={{ env }}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Run first query
                        </Link>
                      )
                    }
                  />
                </td>
              </tr>
            )}

            {/* Data rows */}
            {!isLoading &&
              !isError &&
              items.map((item) => {
                const isSelected = selectedNames.has(item.name);
                const progressPct =
                  item.expected > 0
                    ? Math.min(100, Math.round(((item.executions + item.errors) / item.expected) * 100))
                    : 0;

                return (
                  <tr
                    key={item.name}
                    className={cn(
                      'border-b border-[color:var(--border)] transition-colors',
                      'hover:bg-[color:var(--bg-2)]',
                      isSelected && 'bg-[color:var(--bg-2)]',
                    )}
                  >
                    {/* Checkbox */}
                    <td className="px-4 py-3 w-10">
                      <input
                        type="checkbox"
                        aria-label={`Select query ${item.name}`}
                        checked={isSelected}
                        onChange={() => toggleRow(item.name)}
                        className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                      />
                    </td>

                    {/* Query text — link-blue, navigates to detail by internal name */}
                    <td className="px-4 py-3">
                      <Link
                        to="/_app/env/$env/queries/$name"
                        params={{ env, name: item.name }}
                        className={cn(
                          'text-[color:var(--text-link)] hover:underline',
                          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                          'rounded text-sm font-medium font-mono-tabular',
                        )}
                        title={item.query}
                      >
                        {item.query}
                      </Link>
                    </td>

                    {/* Creator */}
                    <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                      {item.creator}
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <QueryStatusBadge q={item} />
                    </td>

                    {/* Type chip */}
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide',
                          item.type === 'carve'
                            ? 'bg-[rgba(var(--info-r,103),var(--info-g,192),var(--info-b,255),0.12)] text-[color:var(--info)]'
                            : 'bg-[rgba(var(--signal-r,43),var(--signal-g,196),var(--signal-b,190),0.12)] text-[color:var(--signal)]',
                        )}
                      >
                        {item.type}
                      </span>
                    </td>

                    {/* Progress */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 rounded-full bg-[color:var(--bg-2)] overflow-hidden">
                          <div
                            className="h-full rounded-full bg-[color:var(--signal)] transition-[width]"
                            style={{ width: `${progressPct}%` }}
                          />
                        </div>
                        <span className="font-mono-tabular text-xs text-[color:var(--text-2)]">
                          {item.executions}/{item.expected}
                        </span>
                        {item.errors > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.12)] text-[color:var(--danger)]">
                            {item.errors} err
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Created at — relative time */}
                    <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                      <span title={item.created_at}>{formatRelative(item.created_at)}</span>
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
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
      {selectedNames.size > 0 && (
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
            {selectedNames.size} selected
          </span>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />

          {bulkError && (
            <span className="text-xs text-[color:var(--danger)]">{bulkError}</span>
          )}

          <button
            type="button"
            disabled={bulkMutation.isPending}
            aria-label="Complete selected queries"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
            onClick={() =>
              bulkMutation.mutate({
                names: Array.from(selectedNames),
                action: 'complete',
              })
            }
          >
            Complete
          </button>
          <button
            type="button"
            disabled={bulkMutation.isPending}
            aria-label="Expire selected queries"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--warning)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
            onClick={() =>
              bulkMutation.mutate({
                names: Array.from(selectedNames),
                action: 'expire',
              })
            }
          >
            Expire
          </button>
          <button
            type="button"
            disabled={bulkMutation.isPending}
            aria-label="Delete selected queries"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
            onClick={() =>
              bulkMutation.mutate({
                names: Array.from(selectedNames),
                action: 'delete',
              })
            }
          >
            Delete
          </button>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          <button
            type="button"
            aria-label="Clear selection"
            onClick={() => setSelectedNames(new Set())}
            className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
}

export default QueriesListPage;
