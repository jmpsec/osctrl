import { useState } from 'react';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listSavedQueries,
  createSavedQuery,
  updateSavedQuery,
  deleteSavedQuery,
} from '$/api/saved-queries';
import { AuthError } from '$/api/client';
import type {
  SavedQuery,
  SavedQuerySortColumn,
  SortDir,
  SavedQueriesPagedResponse,
} from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SearchInput } from '$/components/data/SearchInput';
import { SortableHeader } from '$/components/data/SortableHeader';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { ModalShell } from '$/components/feedback/ModalShell';

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; query: SavedQuery }
  | { kind: 'delete'; query: SavedQuery };

export function SavedQueriesPage() {
  const { env } = useParams({ from: '/_app/env/$env/saved-queries' });
  const search = useSearch({ from: '/_app/env/$env/saved-queries' });
  const navigate = useNavigate({ from: '/_app/env/$env/saved-queries' });
  const qc = useQueryClient();

  const q: string = search.q ?? '';
  const sort: SavedQuerySortColumn = (search.sort as SavedQuerySortColumn) ?? 'created';
  const dir: SortDir = (search.dir as SortDir) ?? 'desc';
  const page: number = (search.page as number) ?? 1;
  const pageSize: number = (search.page_size as number) ?? 50;

  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

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

  const queryKey = ['saved-queries', env, { q, sort, dir, page, pageSize }] as const;

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () =>
      listSavedQueries({
        env,
        q: q || undefined,
        sort,
        dir,
        page,
        pageSize,
      }),
    staleTime: 15_000,
    refetchInterval: 15_000,
    placeholderData: (prev: SavedQueriesPagedResponse | undefined) => prev,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const items = data?.items ?? [];
  const totalItems = data?.total_items ?? 0;
  const totalPages = data?.total_pages ?? 0;

  function handleSortChange(col: SavedQuerySortColumn, newDir: SortDir) {
    updateSearch({ sort: col, dir: newDir, page: 1 });
  }

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['saved-queries', env] });
    void refetch();
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Toolbar ── */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Saved queries
        </h1>

        <div className="flex-1 max-w-xs">
          <SearchInput
            value={q}
            onChange={(v) => updateSearch({ q: v || undefined, page: 1 })}
            placeholder="Search saved queries…"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setModal({ kind: 'create' })}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            New saved query
          </button>

          <label htmlFor="sq-page-size" className="sr-only">Rows per page</label>
          <select
            id="sq-page-size"
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

      {/* ── Table ── */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <SortableHeader
                column={'name' as SavedQuerySortColumn}
                label="Name"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <SortableHeader
                column={'creator' as SavedQuerySortColumn}
                label="Creator"
                currentSort={sort}
                currentDir={dir}
                onSortChange={handleSortChange}
              />
              <th
                scope="col"
                className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                SQL
              </th>
              <SortableHeader
                column={'updated' as SavedQuerySortColumn}
                label="Updated"
                currentSort={sort}
                currentDir={dir}
                defaultDir="desc"
                onSortChange={handleSortChange}
              />
              <th scope="col" className="px-4 py-3 w-1" />
            </tr>
          </thead>

          <tbody data-stale={isFetching && !isLoading ? 'true' : undefined}>
            {isLoading &&
              Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} cells={5} />)}

            {isError && !isLoading && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={error instanceof Error ? error.message : 'Failed to load saved queries'}
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
                <td colSpan={5}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z" />
                      </svg>
                    }
                    title={q ? 'No saved queries match your search.' : 'No saved queries yet.'}
                    action={
                      q ? (
                        <button
                          type="button"
                          onClick={() => updateSearch({ q: undefined, page: 1 })}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Clear search
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setModal({ kind: 'create' })}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                        >
                          Save your first query
                        </button>
                      )
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              items.map((item) => (
                <tr
                  key={item.id}
                  className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                >
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium font-mono-tabular text-[color:var(--text-1)]">
                      {item.name}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    {item.creator}
                  </td>
                  <td className="px-4 py-3 max-w-md">
                    <code
                      className="block truncate font-mono-tabular text-xs text-[color:var(--text-2)]"
                      title={item.query}
                    >
                      {item.query}
                    </code>
                  </td>
                  <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                    <span title={item.updated_at}>{formatRelative(item.updated_at)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    {/*
                      Run: navigate to queries/new with the saved SQL prefilled
                      and the saved name carried along so the run page can
                      surface a "Running saved query: foo" context label.
                      Uses TanStack's typed Link so the search params survive
                      the validateSearch schema on the queries/new route.
                    */}
                    <Link
                      to="/_app/env/$env/queries/new"
                      params={{ env }}
                      search={{ sql: item.query, name: item.name }}
                      className={cn(
                        'px-2 py-1 text-xs font-medium rounded',
                        'text-[color:var(--signal)] hover:bg-[color:var(--bg-2)]',
                        'transition-colors',
                        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                      )}
                    >
                      Run
                    </Link>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'edit', query: item })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'delete', query: item })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
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

      {/* ── Modals ── */}
      {modal.kind === 'create' && (
        <SavedQueryFormModal
          env={env}
          mode="create"
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'edit' && (
        <SavedQueryFormModal
          env={env}
          mode="edit"
          initial={modal.query}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'delete' && (
        <DeleteConfirmModal
          env={env}
          query={modal.query}
          onClose={() => setModal({ kind: 'closed' })}
          onDeleted={invalidate}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create/Edit modal
// ---------------------------------------------------------------------------
function SavedQueryFormModal({
  env,
  mode,
  initial,
  onClose,
  onSaved,
}: {
  env: string;
  mode: 'create' | 'edit';
  initial?: SavedQuery;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [sql, setSql] = useState(initial?.query ?? 'SELECT * FROM osquery_info;');
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      const trimmedName = name.trim();
      const trimmedSql = sql.trim();
      if (mode === 'create') {
        if (!trimmedName) throw new Error('Name is required');
        if (!trimmedSql) throw new Error('Query SQL is required');
        return createSavedQuery(env, { name: trimmedName, query: trimmedSql });
      }
      if (!initial) throw new Error('Missing original saved query');
      if (!trimmedSql) throw new Error('Query SQL is required');
      return updateSavedQuery(env, initial.name, { query: trimmedSql });
    },
    onSuccess: () => {
      onSaved();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  return (
    <ModalShell
      title={mode === 'create' ? 'Save query' : `Edit ${initial?.name ?? ''}`}
      titleId="sq-form-modal-title"
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
          <label
            htmlFor="sq-name"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            Name
          </label>
          <input
            id="sq-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={mode === 'edit'}
            placeholder="e.g. linux_processes_with_listening_ports"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          />
          {mode === 'edit' && (
            <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
              Names can't be changed after creation.
            </p>
          )}
        </div>

        <div>
          <label
            id="sq-sql-label"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            SQL
          </label>
          <CodeEditor
            value={sql}
            onChange={setSql}
            language="sql"
            height="220px"
            aria-labelledby="sq-sql-label"
          />
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
            disabled={mutation.isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : mode === 'create' ? 'Save query' : 'Save changes'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Delete confirmation modal
// ---------------------------------------------------------------------------
function DeleteConfirmModal({
  env,
  query,
  onClose,
  onDeleted,
}: {
  env: string;
  query: SavedQuery;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => deleteSavedQuery(env, query.name),
    onSuccess: () => {
      onDeleted();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  return (
    <ModalShell
      title="Delete saved query"
      titleId="sq-delete-modal-title"
      onClose={onClose}
    >
      <p className="text-sm text-[color:var(--text-1)]">
        Delete{' '}
        <strong className="font-mono-tabular text-[color:var(--text-1)]">{query.name}</strong>
        ? This cannot be undone.
      </p>

      {err && (
        <p
          role="alert"
          className="mt-3 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
        >
          {err}
        </p>
      )}

      <div className="flex items-center justify-end gap-2 mt-4">
        <button
          type="button"
          onClick={onClose}
          className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate()}
          className={cn(
            'px-3 py-1.5 text-xs font-medium rounded-md',
            'bg-[color:var(--danger)] text-white hover:opacity-90',
            'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--danger)]',
            'disabled:opacity-50 disabled:cursor-not-allowed',
          )}
        >
          {mutation.isPending ? 'Deleting…' : 'Delete'}
        </button>
      </div>
    </ModalShell>
  );
}

export default SavedQueriesPage;
