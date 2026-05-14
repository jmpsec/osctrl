import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listUsers,
  setUserPermissions,
  refreshUserToken,
  deleteUserToken,
} from '$/api/users';
import { AuthError, ApiError } from '$/api/client';
import type { AdminUser, EnvAccess, TokenResponse } from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'permissions'; user: AdminUser }
  | { kind: 'token'; user: AdminUser };

export function UsersPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: () => listUsers(),
    staleTime: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const users = data ?? [];

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['users'] });
    void refetch();
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Operators
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Super-admin view. Per-env permissions and API token management.
        </p>
      </div>

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Username
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Email
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Role
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Last access
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
                    title={error instanceof Error ? error.message : 'Failed to load users'}
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

            {!isLoading && !isError && users.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="9" cy="7" r="4" />
                        <path d="M3 21v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
                      </svg>
                    }
                    title="No users."
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              users.map((u) => (
                <tr
                  key={u.id}
                  className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                >
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium font-mono-tabular text-[color:var(--text-1)]">
                      {u.username}
                    </span>
                    {u.fullname && (
                      <span className="ml-2 text-xs text-[color:var(--text-3)]">{u.fullname}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    {u.email || '—'}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {u.admin && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--signal-r),var(--signal-g),var(--signal-b),0.12)] text-[color:var(--signal)]">
                        admin
                      </span>
                    )}
                    {u.service && (
                      <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.12)] text-[color:var(--info)]">
                        service
                      </span>
                    )}
                    {!u.admin && !u.service && (
                      <span className="text-[color:var(--text-3)]">operator</span>
                    )}
                  </td>
                  <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                    <span title={u.last_access}>{formatRelative(u.last_access)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'permissions', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Permissions…
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'token', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Token…
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {modal.kind === 'permissions' && (
        <PermissionsModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'token' && (
        <TokenModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Permissions modal
// ---------------------------------------------------------------------------
function PermissionsModal({
  user,
  onClose,
  onSaved,
}: {
  user: AdminUser;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [envUuid, setEnvUuid] = useState('');
  const [access, setAccess] = useState<EnvAccess>({
    user: true,
    query: false,
    carve: false,
    admin: false,
  });
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => {
      const trimmed = envUuid.trim();
      if (!trimmed) throw new Error('env_uuid is required');
      return setUserPermissions(user.username, { env_uuid: trimmed, access });
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
      if (e instanceof ApiError && e.status === 404) {
        setErr('Environment not found.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  return (
    <ModalShell
      title={`Permissions for ${user.username}`}
      titleId="user-perms-modal-title"
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
          <label htmlFor="perm-env-uuid" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Environment UUID
          </label>
          <input
            id="perm-env-uuid"
            type="text"
            value={envUuid}
            onChange={(e) => setEnvUuid(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
          <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
            Environment-list dropdown arrives with (Environments CRUD).
          </p>
        </div>

        <fieldset className="space-y-2 border border-[color:var(--border)] rounded-md p-3">
          <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">
            Access
          </legend>
          {(['user', 'query', 'carve', 'admin'] as const).map((k) => (
            <label key={k} className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={access[k]}
                onChange={(e) => setAccess((a) => ({ ...a, [k]: e.target.checked }))}
                className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
              />
              <span className="font-mono-tabular">{k}</span>
              <span className="text-[color:var(--text-3)]">
                {k === 'user' && '— see this env in the SPA'}
                {k === 'query' && '— run distributed queries'}
                {k === 'carve' && '— initiate file carves'}
                {k === 'admin' && '— manage env settings + tags + users'}
              </span>
            </label>
          ))}
        </fieldset>

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
            {mutation.isPending ? 'Saving…' : 'Save permissions'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Token modal — refresh or delete a user's API token
// ---------------------------------------------------------------------------
function TokenModal({
  user,
  onClose,
}: {
  user: AdminUser;
  onClose: () => void;
}) {
  const [token, setToken] = useState<TokenResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const refreshMutation = useMutation({
    mutationFn: () => refreshUserToken(user.username),
    onSuccess: (data) => {
      setToken(data);
      setErr(null);
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Refresh failed');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteUserToken(user.username),
    onSuccess: () => {
      setToken(null);
      setErr(null);
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
      title={`API token — ${user.username}`}
      titleId="user-token-modal-title"
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          Refresh generates a new JWT and invalidates the previous one. Delete
          clears the token entirely — any clients using the old token will
          immediately stop working.
        </p>

        {token && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-[color:var(--text-2)]">
              New token (shown once — copy it now):
            </p>
            <textarea
              readOnly
              value={token.token}
              className={cn(
                'w-full h-24 px-3 py-2 text-xs rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              )}
              onFocus={(e) => e.currentTarget.select()}
            />
            <p className="text-[10px] text-[color:var(--text-3)]">
              Expires: {new Date(token.expires).toLocaleString()}
            </p>
          </div>
        )}

        {err && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {err}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 flex-wrap">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Close
          </button>
          <button
            type="button"
            disabled={refreshMutation.isPending}
            onClick={() => refreshMutation.mutate()}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {refreshMutation.isPending ? 'Refreshing…' : 'Refresh token'}
          </button>
          {confirmDelete ? (
            <button
              type="button"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate()}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--danger)] text-white hover:opacity-90',
                'transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
            >
              {deleteMutation.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors"
            >
              Delete token…
            </button>
          )}
        </div>
      </div>
    </ModalShell>
  );
}

export default UsersPage;
