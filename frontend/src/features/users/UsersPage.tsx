import { useState, useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listUsers,
  getUserPermissions,
  setUserPermissions,
  setUserPermissionsAllSafe,
  refreshUserToken,
  deleteUserToken,
  createUser,
  deleteUser,
  adminResetUserPassword,
  getMe,
} from '$/api/users';
import type { BulkSetReport } from '$/api/users';
import { listEnvironments } from '$/api/environments';
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
  | { kind: 'token'; user: AdminUser }
  | { kind: 'create' }
  | { kind: 'delete'; user: AdminUser }
  | { kind: 'reset-pw'; user: AdminUser };

export function UsersPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: () => listUsers(),
    staleTime: 30_000,
  });

  // Need the current operator's username so the delete button can be
  // suppressed on their own row (server-side guard also rejects
  // self-delete with 400, but hiding the button avoids surprise).
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const users = data ?? [];

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['users'] });
    // Also invalidate the per-user permissions cache so the next
    // open of the Permissions modal sees fresh data instead of
    // whatever was loaded the first time.
    void qc.invalidateQueries({ queryKey: ['user-permissions'] });
    void refetch();
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Operators
        </h1>
        <p className="text-xs text-[color:var(--text-3)] flex-1">
          Super-admin view. Per-env permissions and API token management.
        </p>
        <button
          type="button"
          onClick={() => setModal({ kind: 'create' })}
          className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
        >
          + Add user
        </button>
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
                    {u.auth_source === 'oidc' && (
                      <span
                        className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.10)] text-[color:var(--info)] uppercase tracking-wider"
                        title="JIT-provisioned via federated login (OIDC)"
                      >
                        OIDC
                      </span>
                    )}
                    {u.auth_source === 'saml' && (
                      <span
                        className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.10)] text-[color:var(--info)] uppercase tracking-wider"
                        title="JIT-provisioned via federated login (SAML)"
                      >
                        SAML
                      </span>
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
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'reset-pw', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Reset password…
                    </button>
                    {me?.username !== u.username && (
                      <button
                        type="button"
                        onClick={() => setModal({ kind: 'delete', user: u })}
                        className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.10)] transition-colors"
                      >
                        Delete…
                      </button>
                    )}
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
      {modal.kind === 'create' && (
        <CreateUserModal
          onClose={() => setModal({ kind: 'closed' })}
          onCreated={invalidate}
        />
      )}
      {modal.kind === 'delete' && (
        <DeleteUserModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onDeleted={invalidate}
        />
      )}
      {modal.kind === 'reset-pw' && (
        <ResetPasswordModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={() => setModal({ kind: 'closed' })}
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

  // Pull the env list so we can render a dropdown of name → uuid
  // mappings. Falls back to a free-text input on query error so an
  // operator can still type a UUID manually if the env-list endpoint
  // is flaky. The user opening this modal is necessarily a super-
  // admin (UsersPage gates on admin-level), so /api/v1/environments
  // is reachable.
  const { data: envs, isLoading: envsLoading, error: envsError } = useQuery({
    queryKey: ['environments-for-permissions'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
    retry: 1,
  });

  // Pull the target user's CURRENT permission map so the modal can
  // prefill the access checkboxes with what's already in the DB.
  // Without this the modal opened with a fresh {user:true,...}
  // default — re-saving silently overwrote any prior grants the
  // operator might not have remembered to leave alone.
  //
  // Refetch when the modal opens (queryKey includes user.username).
  // staleTime=0 so we always see the latest state when the modal is
  // re-opened after a save.
  const { data: existingPerms } = useQuery({
    queryKey: ['user-permissions', user.username],
    queryFn: () => getUserPermissions(user.username),
    staleTime: 0,
  });

  // When the operator picks an env in the dropdown, sync the
  // checkboxes to the user's existing access for that env. An env
  // with no rows in existingPerms.permissions falls back to a
  // zero-value EnvAccess (everything false) so the modal shows
  // "this user has no access here yet" honestly.
  useEffect(() => {
    if (!envUuid) return;
    const found = existingPerms?.permissions?.[envUuid];
    if (found) {
      setAccess(found);
    } else {
      setAccess({ user: false, query: false, carve: false, admin: false });
    }
  }, [envUuid, existingPerms]);

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

  // Bulk-apply state. Two-step UX: first click reveals a confirmation
  // pane ("This will apply to N environments — continue?"), second
  // click fires setUserPermissionsAllSafe. The confirmation
  // intentionally NOT a window.confirm — the modal is already a
  // dialog, so a native confirm would be a dialog inside a dialog.
  const [bulkConfirm, setBulkConfirm] = useState<boolean>(false);
  const [bulkReport, setBulkReport] = useState<BulkSetReport | null>(null);
  const bulkMutation = useMutation({
    mutationFn: () => {
      const envUuids = (envs ?? []).map((e) => e.uuid);
      return setUserPermissionsAllSafe(user.username, access, envUuids);
    },
    onSuccess: (report) => {
      setBulkReport(report);
      if (report.failed.length === 0) {
        onSaved();
      }
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Bulk apply failed');
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
            Environment
          </label>
          {envsError ? (
            // Fall back to free-text UUID input on env-list error so an
            // operator is never blocked from setting permissions by a
            // flaky /environments endpoint.
            <>
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
                Couldn't load environments — paste a UUID manually.
              </p>
            </>
          ) : (
            <select
              id="perm-env-uuid"
              value={envUuid}
              onChange={(e) => setEnvUuid(e.target.value)}
              disabled={envsLoading}
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                'disabled:opacity-60',
              )}
            >
              <option value="">
                {envsLoading ? 'Loading environments…' : 'Select an environment'}
              </option>
              {envs?.map((e) => (
                // value is the UUID — that's what setUserPermissions
                // expects on the wire and what the backend's
                // /users/{u}/permissions handler matches against.
                // The visible label is the human name so operators
                // pick by what they know.
                <option key={e.uuid} value={e.uuid}>
                  {e.name}
                </option>
              ))}
            </select>
          )}
          <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
            Permissions are env-scoped — repeat this form to grant access in
            multiple environments.
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

        {/* Bulk-apply result panel. Hidden until bulkMutation completes. */}
        {bulkReport && (
          <div
            role="status"
            className={cn(
              'text-xs px-3 py-2 rounded-md',
              bulkReport.failed.length === 0
                ? 'text-[color:var(--success)] bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)]'
                : 'text-[color:var(--warning)] bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.08)]',
            )}
          >
            Applied access to {bulkReport.succeeded} of {bulkReport.total} environments
            {bulkReport.usedBulkEndpoint ? ' (bulk endpoint)' : ' (per-env fallback)'}.
            {bulkReport.failed.length > 0 && (
              <span className="block mt-1">
                {bulkReport.failed.length} failed — re-run to retry or set individually.
              </span>
            )}
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 flex-wrap">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Cancel
          </button>
          {/* "Apply to all environments" button. Two-step:
              first click → confirmation pill; second click → fire.
              Disabled when env-list query is loading or in error
              state (we have no UUIDs to enumerate). */}
          {bulkConfirm ? (
            <button
              type="button"
              disabled={bulkMutation.isPending}
              onClick={() => bulkMutation.mutate()}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--warning)] text-black hover:opacity-90',
                'transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
              title={`Will apply the selected access to all ${envs?.length ?? 0} environments`}
            >
              {bulkMutation.isPending
                ? `Applying to ${envs?.length ?? 0}…`
                : `Confirm: apply to all ${envs?.length ?? 0} envs`}
            </button>
          ) : (
            <button
              type="button"
              disabled={!envs || envs.length === 0 || envsLoading}
              onClick={() => setBulkConfirm(true)}
              className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title="Grant the selected access to every environment in the system"
            >
              Apply to all envs…
            </button>
          )}
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

// ====================================================================
// CreateUserModal — super-admin "Add user" form (username/email/
// fullname/password + admin/service flags). Posts to the legacy
// UserActionHandler add path. Closes + invalidates the user list on
// success.
// ====================================================================
function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [fullname, setFullname] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      // Match the same character class the backend enforces on
      // federated logins (pkg/auth.sanitizeUsername:
      // ^[a-zA-Z0-9_-]{1,64}$). The password-create flow doesn't
      // strictly enforce this server-side at create time, but
      // pre-validating client-side prevents creating users that
      // can't be addressed via the URL-encoded paths the rest of
      // the API uses.
      const trimmed = username.trim();
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(trimmed)) {
        throw new Error(
          'Username must be 1-64 chars, letters/digits/dash/underscore only.',
        );
      }
      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters.');
      }
      return createUser({
        username: trimmed,
        password,
        email: email.trim(),
        fullname: fullname.trim(),
        admin: isAdmin,
      });
    },
    onSuccess: () => {
      onCreated();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      // ApiError surfaces the server-side message verbatim
      // ("user X already exists", validation failures, etc.).
      setErr(e instanceof Error ? e.message : 'Create failed');
    },
  });

  return (
    <ModalShell title="Add operator" titleId="create-user-modal-title" onClose={onClose}>
      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          setErr(null);
          mutation.mutate();
        }}
        className="space-y-3"
      >
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Username <span className="text-[color:var(--danger)]">*</span>
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            required
            placeholder="e.g. alice"
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Password <span className="text-[color:var(--danger)]">*</span>
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            placeholder="At least 8 characters"
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="optional"
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Full name
          </label>
          <input
            type="text"
            value={fullname}
            onChange={(e) => setFullname(e.target.value)}
            placeholder="optional"
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)] cursor-pointer">
          <input
            type="checkbox"
            checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
            className="accent-[color:var(--signal)]"
          />
          <span>
            Super-admin{' '}
            <span className="text-[color:var(--text-3)]">
              (full access across all environments)
            </span>
          </span>
        </label>

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
            disabled={mutation.isPending || !username || !password}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Creating…' : 'Create operator'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ====================================================================
// DeleteUserModal — confirmation step + server call. Server-side
// guard already prevents self-deletion; we additionally hide the
// Delete button on the current operator's row.
// ====================================================================
function DeleteUserModal({
  user,
  onClose,
  onDeleted,
}: {
  user: AdminUser;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => deleteUser(user.username),
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

  // Belt-and-braces confirmation: even with the modal's visual
  // confirm step, fire a browser-native window.confirm before the
  // mutation actually runs. Cheap insurance against any future
  // accidental-fire path (focused button + keystroke, autofocus,
  // etc.) since "user deleted by mistake" is non-recoverable.
  function confirmDelete() {
    const ok = window.confirm(
      `Permanently delete operator "${user.username}"?\n\nThis cannot be undone.`,
    );
    if (!ok) return;
    mutation.mutate();
  }

  return (
    <ModalShell
      title={`Delete operator — ${user.username}`}
      titleId="delete-user-modal-title"
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This will permanently remove <strong>{user.username}</strong> and all
          their per-environment permissions. The user&apos;s API token (if any)
          will stop working immediately.
        </p>
        <p className="text-xs text-[color:var(--text-3)]">
          Federated identities (OIDC/SAML) will be re-JIT-provisioned with zero
          permissions on next login if you have JIT enabled. To prevent
          re-login, also disable the identity at your IdP.
        </p>

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
            type="button"
            disabled={mutation.isPending}
            onClick={confirmDelete}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--danger)] text-white hover:opacity-90',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Deleting…' : `Delete ${user.username}`}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ====================================================================
// ResetPasswordModal — super-admin "set someone else's password"
// flow. Posts to UserActionHandler's edit case which calls
// h.Users.ChangePassword. The user themself can still self-change
// at /_app/profile with their old password; this is the operator-
// recovery path for "alice forgot her password."
// ====================================================================
function ResetPasswordModal({
  user,
  onClose,
  onSaved,
}: {
  user: AdminUser;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      if (password !== confirm) throw new Error('Passwords do not match.');
      if (password.length < 8) throw new Error('Password must be at least 8 characters.');
      return adminResetUserPassword(user.username, password);
    },
    onSuccess: () => {
      onSaved();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Password change failed');
    },
  });

  return (
    <ModalShell
      title={`Reset password — ${user.username}`}
      titleId="reset-pw-modal-title"
      onClose={onClose}
    >
      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          setErr(null);
          mutation.mutate();
        }}
        className="space-y-3"
      >
        <p className="text-xs text-[color:var(--text-3)]">
          Setting a new password for{' '}
          <strong className="text-[color:var(--text-1)]">{user.username}</strong>.
          The user will need to log in with the new password; any existing API
          tokens stay valid until explicitly revoked.
        </p>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            New password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
            minLength={8}
            placeholder="At least 8 characters"
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Confirm new password
          </label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
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
            disabled={mutation.isPending || !password || !confirm}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : 'Set password'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

export default UsersPage;
