import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { assignNodeExtension, getNodeExtensions, unassignNodeExtension } from '$/api/extensions';
import type { NodeExtensionStatus, NodeExtensions } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { plainBtn, warnBtn } from './overrideShared';

const fmt = (iso: string | null) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
};

/** Host-reported error and time are untrusted: plain text only. */
function statusText(s: NodeExtensionStatus): string {
  // An ok status may carry a note, e.g. that extensions are disabled by flags.
  if (s.result === 'ok') return s.error ? `ok: ${s.error}` : 'ok';
  const head = `${s.result} ${fmt(s.at ?? s.reported_at)}`;
  return s.error ? `${head}: ${s.error}` : head;
}

/** rejected: an install failed; kept: a removal failed, it is still on the host. */
const failed = (s: NodeExtensionStatus) => s.result === 'rejected' || s.result === 'kept';

/**
 * What osctrld runs on one host: the effective extensions (environment +
 * this host), their last reported status, and, for super admins, command-execution
 * assignments.
 */
export function NodeExtensionsView({ env, uuid, hostname }: { env: string; uuid: string; hostname: string }) {
  const qc = useQueryClient();
  // Shared with NodeDetailPage (banner + tab dot): keep the key in sync.
  const queryKey = ['node-extensions', env, uuid];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getNodeExtensions(env, uuid),
    staleTime: 10_000,
  });

  const [allowOpen, setAllowOpen] = useState(false);
  const [pick, setPick] = useState('');
  const [expiry, setExpiry] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [allowError, setAllowError] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<number | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const done = (resp: NodeExtensions) => qc.setQueryData(queryKey, resp);

  function closeAllow() {
    setAllowOpen(false);
    setPick('');
    setExpiry('');
    setAcknowledged(false);
    setAllowError(null);
  }

  const allow = useMutation({
    mutationFn: () => assignNodeExtension(env, uuid, Number(pick), expiry ? new Date(expiry).toISOString() : null),
    onSuccess: (resp) => {
      done(resp);
      closeAllow();
    },
    onError: (e: Error) => setAllowError(e.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => unassignNodeExtension(env, uuid, id),
    onSuccess: (resp) => {
      done(resp);
      setRemoveTarget(null);
      setRemoveError(null);
    },
    onError: (e: Error) => setRemoveError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading extensions…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load extensions'}
      </p>
    );
  }

  const effective = data.effective ?? [];
  const assignments = data.assignments ?? [];
  const status = data.status ?? [];
  const statusOf = (name: string) => status.find((s) => s.name === name);
  const lingering = status.filter((s) => s.lingering);
  // The server sends the library only to super admins.
  const superAdmin = data.library !== null;
  const library = data.library ?? [];
  const removing = assignments.find((a) => a.extension_id === removeTarget);

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-[color:var(--text-3)]">
          osctrld applies extensions on its next sync (up to an hour) and restarts osquery.
        </p>
        {superAdmin && library.length > 0 && (
          <button
            type="button"
            className={buttonClasses({ variant: 'ghost', size: 'sm', className: 'ml-auto' })}
            onClick={() => setAllowOpen(true)}
          >
            Allow command execution
          </button>
        )}
      </div>
      {superAdmin && library.length === 0 && (
        <p className="text-xs text-[color:var(--text-3)]">No command-execution extensions are available in the library.</p>
      )}

      {status.length === 0 && (
        <p className="text-xs text-[color:var(--text-3)]">
          osctrld has not reported on extensions for this host yet. It reports after its next sync (up to an hour).
        </p>
      )}

      {effective.length === 0 ? (
        <p className="text-sm text-[color:var(--text-2)]">No extensions apply to this host.</p>
      ) : (
        <ul className="divide-y divide-[color:var(--border)] border border-[color:var(--border)] rounded-md">
          {effective.map((x) => {
            const st = statusOf(x.name);
            return (
              <li key={`${x.source}:${x.name}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <span className="font-medium text-[color:var(--text-1)]">{x.name}</span>
                <span className="text-xs text-[color:var(--text-3)]">{x.source === 'host' ? 'This host' : 'Environment'}</span>
                {!x.available && (
                  <span className="text-xs text-[color:var(--warning)]">No file for this platform</span>
                )}
                <span
                  className={
                    st && failed(st)
                      ? 'ml-auto text-xs text-[color:var(--danger)] break-all'
                      : 'ml-auto text-xs text-[color:var(--text-3)]'
                  }
                >
                  {st ? statusText(st) : 'no status yet'}
                </span>
              </li>
            );
          })}
        </ul>
      )}

      {lingering.length > 0 && (
        <div className="space-y-1">
          <h3 className="text-xs font-semibold text-[color:var(--danger)]">Removed but still on this host</h3>
          <ul className="divide-y divide-[color:var(--border)] border border-[color:var(--border)] rounded-md">
            {lingering.map((s) => (
              <li key={s.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <code className="font-medium text-[color:var(--text-1)]">{s.name}</code>
                <span className="ml-auto text-xs text-[color:var(--danger)] break-all">{statusText(s)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {assignments.length > 0 && (
        <div className="space-y-1">
          <h3 className="text-xs font-semibold text-[color:var(--text-2)]">Command execution on this host</h3>
          <ul className="divide-y divide-[color:var(--border)] border border-[color:var(--border)] rounded-md">
            {assignments.map((a) => (
              <li key={a.extension_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <code className="font-medium text-[color:var(--text-1)]">{a.name}</code>
                <span className="text-xs text-[color:var(--text-3)]">
                  {`set by ${a.created_by} on ${fmt(a.created_at)}`}
                  {a.expires_at && (a.expired ? `, expired ${fmt(a.expires_at)}` : `, expires ${fmt(a.expires_at)}`)}
                </span>
                {superAdmin && (
                  <button
                    type="button"
                    aria-label={`Remove ${a.name}`}
                    className={buttonClasses({ variant: 'danger', size: 'sm', className: 'ml-auto' })}
                    onClick={() => {
                      setRemoveError(null);
                      setRemoveTarget(a.extension_id);
                    }}
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {allowOpen && (
        <ModalShell
          title={`Allow command execution on ${hostname}?`}
          titleId="node-extensions-allow-title"
          onClose={closeAllow}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              This installs an extension that lets anyone who can query this host run commands on it as root. osctrld installs
              it on its next sync (up to an hour) and restarts osquery. It stays until it is removed or expires.
            </p>
            <label className="flex flex-col gap-1 text-xs text-[color:var(--text-2)]">
              Extension
              <select
                value={pick}
                onChange={(e) => setPick(e.target.value)}
                className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
              >
                <option value="">Select an extension…</option>
                {library.map((x) => (
                  <option key={x.id} value={x.id}>{`${x.name} ${x.version}`}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs text-[color:var(--text-2)]">
              Expires (optional)
              <input
                type="datetime-local"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
              />
            </label>
            <label className="flex items-start gap-2 text-sm text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
                className="mt-0.5"
              />
              I understand this allows running commands on this host and I know what I&apos;m doing
            </label>
            {allowError && (
              <p role="alert" className="text-xs text-[color:var(--danger)]">
                {allowError}
              </p>
            )}
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={closeAllow} disabled={allow.isPending} className={plainBtn}>
                Cancel
              </button>
              <button
                type="button"
                onClick={() => allow.mutate()}
                disabled={!acknowledged || pick === '' || allow.isPending}
                className={warnBtn}
              >
                Allow command execution
              </button>
            </div>
          </div>
        </ModalShell>
      )}

      {removing && (
        <ModalShell
          title={`Remove command execution from ${hostname}?`}
          titleId="node-extensions-remove-title"
          onClose={() => setRemoveTarget(null)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              {`osctrld removes ${removing.name} from this host on its next sync (up to an hour) and restarts osquery.`}
            </p>
            {removeError && (
              <p role="alert" className="text-xs text-[color:var(--danger)]">
                {removeError}
              </p>
            )}
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={() => setRemoveTarget(null)} disabled={remove.isPending} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={() => remove.mutate(removing.extension_id)} disabled={remove.isPending} className={warnBtn}>
                Remove
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}
