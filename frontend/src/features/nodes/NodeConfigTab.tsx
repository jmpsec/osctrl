import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { deleteNodeConfig, getNodeConfig, putNodeConfig } from '$/api/nodes';
import type { NodeConfig } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { DiffView } from '$/components/forms/DiffView';
import { NodeExtensionsView } from './NodeExtensionsView';
import { NodeOsqueryView } from './NodeOsqueryView';
import { NodeFlagsView } from './NodeFlagsView';
import { useOsctrldEnabled } from '$/lib/useOsctrldEnabled';
import { plainBtn, toLocalInput, VIEWS, warnBtn, type View } from './overrideShared';

const EDITOR_LABELS: Record<Exclude<View, 'diff'>, string> = {
  applied: 'Applied configuration',
  environment: 'Environment configuration',
  override: 'Node override configuration',
};

/**
 * Pretty-print both configs with object keys sorted so equal configs serialize
 * identically for the Diff view; if either side is not valid JSON, diff the raw text.
 */
function canonicalPair(a: string, b: string): [string, string] {
  const sort = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sort)
      : v !== null && typeof v === 'object'
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, sort((v as Record<string, unknown>)[k])]),
          )
        : v;
  try {
    return [JSON.stringify(sort(JSON.parse(a)), null, 2), JSON.stringify(sort(JSON.parse(b)), null, 2)];
  } catch {
    return [a, b];
  }
}

function ConfigView({ env, uuid, hostname }: { env: string; uuid: string; hostname: string }) {
  const qc = useQueryClient();
  const queryKey = ['node-config', env, uuid];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getNodeConfig(env, uuid),
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

  const done = (resp: NodeConfig) => qc.setQueryData(queryKey, resp);

  const save = useMutation({
    mutationFn: () =>
      putNodeConfig(env, uuid, {
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
    mutationFn: () => deleteNodeConfig(env, uuid),
    onSuccess: (resp) => {
      done(resp);
      setRemoveOpen(false);
      setRemoveError(null);
    },
    onError: (e: Error) => setRemoveError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading configuration…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load configuration'}
      </p>
    );
  }

  const hasOverride = data.override !== '';

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

  const [diffBefore, diffAfter] = canonicalPair(data.environment, data.applied);
  const overrideEditable = editing && view === 'override';

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Configuration view" className="flex gap-1">
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
              Edit override
            </button>
          )}
          {hasOverride && !editing && (
            <button type="button" className={buttonClasses({ variant: 'danger', size: 'sm' })} onClick={() => setRemoveOpen(true)}>
              Remove override
            </button>
          )}
        </div>
      </div>

      {view === 'diff' ? (
        <DiffView before={diffBefore} after={diffAfter} leftLabel="Environment" rightLabel="Applied" />
      ) : (
        <CodeEditor
          value={view === 'applied' ? data.applied : view === 'environment' ? data.environment : overrideEditable ? draft : data.override}
          onChange={overrideEditable ? setDraft : undefined}
          readOnly={!overrideEditable}
          language="json"
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
          <p className="text-xs text-[color:var(--text-3)]">Changes reach the host on its next configuration fetch.</p>
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
          title={`Override configuration for ${hostname}?`}
          titleId="node-config-unlock-title"
          onClose={closeUnlock}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              This changes what osquery runs on this host only, on top of the environment&apos;s configuration. Settings that keep the
              host connected to osctrl can&apos;t be overridden, but a heavy override can still affect the host. It stays until it is
              removed or expires. Options you set here that the environment doesn&apos;t set stay in effect on the host until osquery
              restarts, even after the override is removed or expires.
            </p>
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
          title={`Remove the configuration override for ${hostname}?`}
          titleId="node-config-remove-title"
          onClose={() => setRemoveOpen(false)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              The host goes back to the environment&apos;s configuration on its next configuration fetch. Options the environment doesn&apos;t set keep their overridden value until
              osquery restarts.
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
                Remove override
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}

type Kind = 'configuration' | 'flags' | 'extensions' | 'osquery';

const KINDS: { id: Kind; label: string }[] = [
  { id: 'configuration', label: 'Configuration' },
  { id: 'flags', label: 'Flags' },
  { id: 'extensions', label: 'Extensions' },
  { id: 'osquery', label: 'Osquery version' },
];

/** Per-node overrides: osquery configuration (JSON), startup flags (flagfile) or extensions. */
export function NodeConfigTab({ env, uuid, hostname }: { env: string; uuid: string; hostname: string }) {
  const [picked, setKind] = useState<Kind>('configuration');
  const { enabled: osctrldEnabled } = useOsctrldEnabled();
  // Flags, extensions and osquery version are all applied by osctrld; without
  // it only the plain configuration override remains, so no switcher.
  const kind: Kind = osctrldEnabled ? picked : 'configuration';
  return (
    <div className="space-y-3">
      {osctrldEnabled && <div role="group" aria-label="Override type" className="flex gap-1">
        {KINDS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            aria-pressed={kind === id}
            onClick={() => setKind(id)}
            className={buttonClasses({ variant: kind === id ? 'primary' : 'ghost', size: 'sm' })}
          >
            {label}
          </button>
        ))}
      </div>}
      {kind === 'configuration' ? (
        <ConfigView env={env} uuid={uuid} hostname={hostname} />
      ) : kind === 'flags' ? (
        <NodeFlagsView env={env} uuid={uuid} hostname={hostname} />
      ) : kind === 'extensions' ? (
        <NodeExtensionsView env={env} uuid={uuid} hostname={hostname} />
      ) : (
        <NodeOsqueryView env={env} uuid={uuid} hostname={hostname} />
      )}
    </div>
  );
}
