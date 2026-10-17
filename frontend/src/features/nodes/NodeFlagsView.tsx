import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { deleteNodeFlags, getNodeFlags, putNodeFlags } from '$/api/nodes';
import type { NodeFlags } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { DiffView } from '$/components/forms/DiffView';
import { plainBtn, toLocalInput, VIEWS, warnBtn, type View } from './overrideShared';

const EDITOR_LABELS: Record<Exclude<View, 'diff'>, string> = {
  applied: 'Applied flags',
  environment: 'Environment flags',
  override: 'Node override flags',
};

const fmt = (iso: string | null) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
};

/** Per-node osquery flags override: view, edit (confirm-to-unlock), expire, remove. */
export function NodeFlagsView({ env, uuid, hostname }: { env: string; uuid: string; hostname: string }) {
  const qc = useQueryClient();
  // Shared with NodeDetailPage (banner + tab dot): keep the key in sync.
  const queryKey = ['node-flags', env, uuid];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getNodeFlags(env, uuid),
    staleTime: 10_000,
  });

  const [view, setView] = useState<View>('applied');
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [expiry, setExpiry] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const done = (resp: NodeFlags) => qc.setQueryData(queryKey, resp);

  const save = useMutation({
    mutationFn: () =>
      putNodeFlags(env, uuid, {
        override: draft,
        expires_at: expiry ? new Date(expiry).toISOString() : null,
      }),
    onSuccess: (resp) => {
      done(resp);
      setEditing(false);
      setSaveError(null);
    },
    onError: (e: Error) => setSaveError(e.message),
  });

  const remove = useMutation({
    mutationFn: () => deleteNodeFlags(env, uuid),
    onSuccess: (resp) => {
      done(resp);
      setRemoveOpen(false);
      setRemoveError(null);
    },
    onError: (e: Error) => setRemoveError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading flags…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load flags'}
      </p>
    );
  }

  const hasOverride = data.override !== '';
  const osctrld = data.osctrld;

  function closeUnlock() {
    setUnlockOpen(false);
    setAcknowledged(false);
  }

  function unlock() {
    closeUnlock();
    setDraft(data!.override);
    setExpiry(data!.expired ? '' : toLocalInput(data!.expires_at));
    setSaveError(null);
    setView('override');
    setEditing(true);
  }

  function cancelEdit() {
    setEditing(false);
    setSaveError(null);
  }

  const overrideEditable = editing && view === 'override';

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Flags view" className="flex gap-1">
          {VIEWS.map(({ id, label }) => (
            <button
              key={id}
              type="button"
              aria-pressed={view === id}
              onClick={() => setView(id)}
              className={buttonClasses({ variant: view === id ? 'primary' : 'ghost', size: 'sm' })}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex gap-2">
          {!editing && (
            <button type="button" className={buttonClasses({ variant: 'ghost', size: 'sm' })} onClick={() => setUnlockOpen(true)}>
              Edit flags override
            </button>
          )}
          {hasOverride && !editing && (
            <button type="button" className={buttonClasses({ variant: 'danger', size: 'sm' })} onClick={() => setRemoveOpen(true)}>
              Remove flags override
            </button>
          )}
        </div>
      </div>

      {/* apply_error / apply_at come from the host: rendered as plain text only. */}
      {osctrld?.rejected_current ? (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {`osquery on this host rejected this override on ${fmt(osctrld.apply_at)} and osctrld restored the environment's flags: ${osctrld.apply_error}`}
        </p>
      ) : (
        <p className="text-xs text-[color:var(--text-3)]">
          {osctrld
            ? `Managed by osctrld — last fetched flags ${fmt(osctrld.last_fetched_at)}`
            : 'No osctrld seen for this host: a flags override will not reach it.'}
        </p>
      )}
      {data.conflicts.length > 0 && (
        <p className="text-xs text-[color:var(--warning)]">
          {`Also set in the configuration's options, which can take precedence: ${data.conflicts.join(', ')}`}
        </p>
      )}

      {view === 'diff' ? (
        <DiffView before={data.environment} after={data.applied} leftLabel="Environment" rightLabel="Applied" />
      ) : (
        <CodeEditor
          value={view === 'applied' ? data.applied : view === 'environment' ? data.environment : overrideEditable ? draft : data.override}
          onChange={overrideEditable ? setDraft : undefined}
          readOnly={!overrideEditable}
          language="plaintext"
          height="420px"
          aria-label={EDITOR_LABELS[view]}
        />
      )}

      {editing && (
        <div className="space-y-3">
          {saveError && (
            <p role="alert" className="text-xs text-[color:var(--danger)]">
              {saveError}
            </p>
          )}
          <p className="text-xs text-[color:var(--text-3)]">osctrld applies changes on its next sync, up to an hour.</p>
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs text-[color:var(--text-2)]">
              Expires (optional)
              <input
                type="datetime-local"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
              />
            </label>
            <button
              type="button"
              className={buttonClasses({ variant: 'primary', size: 'md' })}
              disabled={save.isPending || draft.trim() === ''}
              onClick={() => save.mutate()}
            >
              {save.isPending ? 'Saving…' : 'Save'}
            </button>
            <button type="button" className={buttonClasses({ variant: 'ghost', size: 'md' })} onClick={cancelEdit} disabled={save.isPending}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {unlockOpen && (
        <ModalShell
          title={`Override flags for ${hostname}?`}
          titleId="node-flags-unlock-title"
          onClose={closeUnlock}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              This changes the flags osquery starts with on this host only. osctrld applies it on its next sync (up to an hour) and
              restarts osquery; if osquery won&apos;t start with it, osctrld restores the environment&apos;s flags. Settings that keep
              the host connected to osctrl can&apos;t be overridden. It stays until it is removed or expires.
            </p>
            {!osctrld && (
              <p className="text-sm text-[color:var(--warning)]">
                No osctrld has been seen for this host, so this override won&apos;t reach it until osctrld manages it.
              </p>
            )}
            <label className="flex items-start gap-2 text-sm text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
                className="mt-0.5"
              />
              I understand this changes osquery on this host and I know what I&apos;m doing
            </label>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={closeUnlock} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={unlock} disabled={!acknowledged} className={warnBtn}>
                Unlock editing
              </button>
            </div>
          </div>
        </ModalShell>
      )}

      {removeOpen && (
        <ModalShell
          title={`Remove the flags override for ${hostname}?`}
          titleId="node-flags-remove-title"
          onClose={() => setRemoveOpen(false)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              The host goes back to the environment&apos;s flags on osctrld&apos;s next sync (up to an hour), and osquery restarts.
            </p>
            {removeError && (
              <p role="alert" className="text-xs text-[color:var(--danger)]">
                {removeError}
              </p>
            )}
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={() => setRemoveOpen(false)} disabled={remove.isPending} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={() => remove.mutate()} disabled={remove.isPending} className={warnBtn}>
                Remove flags override
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}
