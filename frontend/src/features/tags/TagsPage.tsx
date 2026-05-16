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
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cells={5} />)}

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
                <td colSpan={5}>
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
              tags.map((tag) => (
                <tr
                  key={tag.id}
                  className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                >
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
              ))}
          </tbody>
        </table>
      </div>

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
