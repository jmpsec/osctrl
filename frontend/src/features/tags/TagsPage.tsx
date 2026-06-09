import { useState } from 'react';
import { useParams, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { listEnvTags, tagsAction } from '$/api/tags';
import { AuthError, ApiError } from '$/api/client';
import type { AdminTag } from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; tag: AdminTag }
  | { kind: 'delete'; tag: AdminTag };

const DEFAULT_COLOR = '#5b8def';
const DEFAULT_ICON = 'fas fa-tag';
const TAG_TYPE_REGULAR = 6; // mirrors pkg/tags.TagTypeTag

export function TagsPage() {
  const { env } = useParams({ from: '/_app/env/$env/tags' });
  const navigate = useNavigate({ from: '/_app/env/$env/tags' });
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  // Multi-select state — matches the dock pattern used on Carves /
  // Queries / Nodes. Tag names are unique per env so the set keys on
  // name without needing to thread an id around.
  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);

  const queryKey = ['tags', env] as const;

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () => listEnvTags(env),
    staleTime: 30_000,
    refetchInterval: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const tags = data ?? [];

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['tags', env] });
    void refetch();
  }

  // Header checkbox state — same pattern as CarvesListPage's toggleAll.
  const allVisibleNames = tags.map((t) => t.name);
  const allChecked =
    allVisibleNames.length > 0 &&
    allVisibleNames.every((n) => selectedNames.has(n));
  const someChecked = allVisibleNames.some((n) => selectedNames.has(n));

  function toggleAll() {
    if (allChecked) {
      setSelectedNames(new Set());
    } else {
      setSelectedNames(new Set(allVisibleNames));
    }
  }

  function toggleOne(name: string) {
    setSelectedNames((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  // Bulk delete — fans out one POST /tags/{env}/remove per name and
  // collects per-name failures so a partial success still reports
  // 'deleted 5 of 7; 2 failed' instead of going red on first reject.
  const bulkDeleteMut = useMutation({
    mutationFn: async (names: string[]) => {
      const settled = await Promise.allSettled(
        names.map((name) =>
          tagsAction(env, 'remove', { name }),
        ),
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;
      return { total: names.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      setSelectedNames(new Set());
      if (failed > 0) {
        setBulkError(`Deleted ${total - failed} of ${total} tag(s); ${failed} failed.`);
      } else {
        setBulkError(null);
      }
      invalidate();
    },
    onError: (err) => {
      if (err instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setBulkError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'Bulk delete failed',
      );
    },
  });

  function handleBulkDelete() {
    const names = Array.from(selectedNames);
    if (names.length === 0) return;
    if (
      !confirm(
        `Delete ${names.length} tag${names.length === 1 ? '' : 's'}?\n\nNodes currently carrying the tag will lose it.`,
      )
    ) {
      return;
    }
    setBulkError(null);
    bulkDeleteMut.mutate(names);
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Tags
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Environment-scoped operator tags for grouping and bulk targeting.
        </p>

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
            New tag
          </button>

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
              <th scope="col" className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  aria-label="Select all visible tags"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked && !allChecked;
                  }}
                  onChange={toggleAll}
                  className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                />
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Tag
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Description
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Created by
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Created
              </th>
              <th scope="col" className="px-4 py-3 w-1" />
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}

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
                    title={error instanceof Error ? error.message : 'Failed to load tags'}
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

            {!isLoading && !isError && tags.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z" />
                      </svg>
                    }
                    title="No tags in this environment yet."
                    action={
                      <button
                        type="button"
                        onClick={() => setModal({ kind: 'create' })}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Create your first tag
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              tags.map((tag) => {
                const isSelected = selectedNames.has(tag.name);
                return (
                <tr
                  key={tag.id}
                  className={cn(
                    'border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors',
                    isSelected && 'bg-[color:var(--signal)]/5',
                  )}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      aria-label={`Select tag ${tag.name}`}
                      checked={isSelected}
                      onChange={() => toggleOne(tag.name)}
                      className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium"
                      style={{
                        backgroundColor: `${tag.color || DEFAULT_COLOR}22`,
                        color: tag.color || DEFAULT_COLOR,
                      }}
                    >
                      <i className={tag.icon || DEFAULT_ICON} aria-hidden />
                      <span className="font-mono-tabular">{tag.name}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    {tag.description || <span className="text-[color:var(--text-3)]">—</span>}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    {tag.created_by || '—'}
                  </td>
                  <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                    <span title={tag.created_at}>{formatRelative(tag.created_at)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'edit', tag })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'delete', tag })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* Multi-select dock — matches CarvesListPage chrome exactly so
          every env-scoped list page reads with one bulk-action voice. */}
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
            disabled={bulkDeleteMut.isPending}
            aria-label="Delete selected tags"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
            onClick={handleBulkDelete}
          >
            {bulkDeleteMut.isPending ? 'Deleting…' : 'Delete'}
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

      {/* Bulk-error toast when no selection remains — same pattern as
          NodesTablePage so the operator sees what happened even after
          the selection clears. */}
      {bulkError && selectedNames.size === 0 && (
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

      {modal.kind === 'create' && (
        <TagFormModal
          env={env}
          mode="create"
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'edit' && (
        <TagFormModal
          env={env}
          mode="edit"
          initial={modal.tag}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'delete' && (
        <DeleteTagModal
          env={env}
          tag={modal.tag}
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
function TagFormModal({
  env,
  mode,
  initial,
  onClose,
  onSaved,
}: {
  env: string;
  mode: 'create' | 'edit';
  initial?: AdminTag;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [color, setColor] = useState(initial?.color || DEFAULT_COLOR);
  const [icon, setIcon] = useState(initial?.icon || DEFAULT_ICON);
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      const trimmedName = name.trim();
      if (!trimmedName) throw new Error('Name is required.');
      const action = mode === 'create' ? 'add' : 'edit';
      return tagsAction(env, action, {
        name: trimmedName,
        description: description.trim(),
        color: color.trim(),
        icon: icon.trim(),
        tagtype: TAG_TYPE_REGULAR,
      });
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
      if (e instanceof ApiError && e.status === 409) {
        setErr('A tag with that name already exists in this environment.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  return (
    <ModalShell
      title={mode === 'create' ? 'Create tag' : `Edit ${initial?.name ?? ''}`}
      titleId="tag-form-modal-title"
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
          <label htmlFor="tag-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Name
          </label>
          <input
            id="tag-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={mode === 'edit'}
            placeholder="e.g. production"
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
          <label htmlFor="tag-desc" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Description
          </label>
          <input
            id="tag-desc"
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What does this tag represent?"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
        </div>

        <div className="flex gap-3">
          <div className="flex-1">
            <label htmlFor="tag-color" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Color
            </label>
            <input
              id="tag-color"
              type="color"
              value={color}
              onChange={(e) => setColor(e.target.value)}
              className="w-16 h-9 rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] cursor-pointer"
            />
          </div>
          <div className="flex-1">
            <label htmlFor="tag-icon" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Icon class
            </label>
            <input
              id="tag-icon"
              type="text"
              value={icon}
              onChange={(e) => setIcon(e.target.value)}
              placeholder={DEFAULT_ICON}
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            />
            <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
              Font Awesome class (e.g. <code>fas fa-server</code>).
            </p>
          </div>
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
            {mutation.isPending ? 'Saving…' : mode === 'create' ? 'Create tag' : 'Save changes'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Delete confirmation modal
// ---------------------------------------------------------------------------
function DeleteTagModal({
  env,
  tag,
  onClose,
  onDeleted,
}: {
  env: string;
  tag: AdminTag;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () => tagsAction(env, 'remove', { name: tag.name }),
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
    <ModalShell title="Delete tag" titleId="tag-delete-modal-title" onClose={onClose}>
      <p className="text-sm text-[color:var(--text-1)]">
        Delete <strong className="font-mono-tabular">{tag.name}</strong>? Any
        nodes tagged with this will become untagged. This cannot be undone.
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

export default TagsPage;
