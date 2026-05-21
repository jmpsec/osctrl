import { useState } from 'react';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation } from '@tanstack/react-query';
import { listCarves, actOnCarve } from '$/api/carves';
import { AuthError } from '$/api/client';
import type {
  CarveTarget,
  CarveSortColumn,
  SortDir,
  CarvesPagedResponse,
} from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { StatusTabs } from '$/components/data/StatusTabs';
import type { StatusTab } from '$/components/data/StatusTabs';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SearchInput } from '$/components/data/SearchInput';
import { SortableHeader } from '$/components/data/SortableHeader';

const CARVE_STATUS_TABS: StatusTab<CarveTarget>[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'completed', label: 'Completed' },
  { value: 'expired', label: 'Expired' },
  { value: 'deleted', label: 'Deleted' },
];

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;

export function CarvesListPage() {
  const { env } = useParams({ from: '/_app/env/$env/carves' });
  const search = useSearch({ from: '/_app/env/$env/carves' });
  const navigate = useNavigate({ from: '/_app/env/$env/carves' });

  const target: CarveTarget = (search.target as CarveTarget) ?? 'all';
  const q: string = search.q ?? '';
  const sort: CarveSortColumn = (search.sort as CarveSortColumn) ?? 'created';
  const dir: SortDir = (search.dir as SortDir) ?? 'desc';
  const page: number = (search.page as number) ?? 1;
  const pageSize: number = (search.page_size as number) ?? 50;

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
  }

  const queryKey = ['carves', env, { target, q, sort, dir, page, pageSize }] as const;

  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () =>
      listCarves({
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
    placeholderData: (prev: CarvesPagedResponse | undefined) => prev,
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
        names.map((name) => actOnCarve(env, name, action)),
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

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const items = data?.items ?? [];
  const totalItems = data?.total_items ?? 0;
  const totalPages = data?.total_pages ?? 0;

  function handleSortChange(col: CarveSortColumn, newDir: SortDir) {
    updateSearch({ sort: col, dir: newDir, page: 1 });
  }

  const allVisible = items.map((c) => c.name);
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

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Carves
        </h1>
        <StatusTabs
          tabs={CARVE_STATUS_TABS}
          value={target}
          onChange={(v) => updateSearch({ target: v, page: 1 })}
        />

        <div className="flex-1 max-w-xs">
          <SearchInput
            value={q}
            onChange={(v) => updateSearch({ q: v || undefined, page: 1 })}
            placeholder="Search carves…"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <Link
            to="/_app/env/$env/carves/new"
            params={{ env }}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            New carve
          </Link>

          <label htmlFor="carves-page-size" className="sr-only">Rows per page</label>
          <select
            id="carves-page-size"
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

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="w-10 px-4 py-3">
                <input
                  type="checkbox"
                  checked={allChecked}
                  ref={(el) => { if (el) el.indeterminate = someChecked && !allChecked; }}
                  onChange={toggleAll}
                  aria-label="Select all visible carves"
                  className="accent-[color:var(--signal)]"
                />
              </th>
              <SortableHeader
                column={'name' as CarveSortColumn}
                label="Name"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <th
                scope="col"
                className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                Path
              </th>
              <SortableHeader
                column={'creator' as CarveSortColumn}
                label="Creator"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column={'executions' as CarveSortColumn}
                label="Progress"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column={'created' as CarveSortColumn}
                label="Created"
                currentSort={sort}
                currentDir={dir}
                defaultDir="desc"
                onSortChange={handleSortChange}
              />
            </tr>
          </thead>

          <tbody data-stale={isFetching && !isLoading ? 'true' : undefined}>
            {isLoading &&
              Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}

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
                    title={error instanceof Error ? error.message : 'Failed to load carves'}
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

            {!isLoading && !isError && items.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M3 7h18v10a2 2 0 01-2 2H5a2 2 0 01-2-2zM3 7l3-3h12l3 3" />
                      </svg>
                    }
                    title={q || target !== 'all' ? 'No carves match.' : 'No carves yet.'}
                    action={
                      q || target !== 'all' ? (
                        <button
                          type="button"
                          onClick={() => updateSearch({ q: undefined, target: 'all', page: 1 })}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Clear filters
                        </button>
                      ) : (
                        <Link
                          to="/_app/env/$env/carves/new"
                          params={{ env }}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Start first carve
                        </Link>
                      )
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              items.map((item) => {
                const progressPct =
                  item.expected > 0
                    ? Math.min(
                        100,
                        Math.round(((item.executions + item.errors) / item.expected) * 100),
                      )
                    : 0;
                return (
                  <tr
                    key={item.name}
                    className={cn(
                      'border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors',
                      selectedNames.has(item.name) && 'bg-[color:var(--signal)]/5',
                    )}
                  >
                    <td className="w-10 px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedNames.has(item.name)}
                        onChange={() => toggleRow(item.name)}
                        aria-label={`Select ${item.name}`}
                        className="accent-[color:var(--signal)]"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        to="/_app/env/$env/carves/$name"
                        params={{ env, name: item.name }}
                        className={cn(
                          'text-sm font-medium font-mono-tabular text-[color:var(--text-link)]',
                          'hover:underline',
                        )}
                      >
                        {item.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <code
                        className="block truncate font-mono-tabular text-xs text-[color:var(--text-2)]"
                        title={item.path}
                      >
                        {item.path || '—'}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                      {item.creator}
                    </td>
                    <td className="px-4 py-3 text-xs tnum text-[color:var(--text-2)]">
                      <span title={`${item.executions}/${item.expected} (errors: ${item.errors})`}>
                        {item.executions + item.errors}/{item.expected || '—'}
                        {item.expected > 0 && ` · ${progressPct}%`}
                      </span>
                    </td>
                    <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                      <span title={item.created_at}>{formatRelative(item.created_at)}</span>
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
            aria-label="Complete selected carves"
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
            aria-label="Expire selected carves"
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
            aria-label="Delete selected carves"
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

export default CarvesListPage;
