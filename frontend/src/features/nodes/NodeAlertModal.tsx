import { useState } from 'react';
import { ModalShell } from '$/components/feedback/ModalShell';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createAlertRule, applyAlerts, listAlertChannels, type AlertChannel } from '$/api/alerts';
import { useQuery } from '@tanstack/react-query';
import { AuthError } from '$/api/client';

/**
 * NodeAlertModal — the node detail page's "alert on this node" flow.
 *
 * Offers the two node-scoped rule types that make sense per-node from an
 * operator's point of view:
 *   - "Node goes inactive": fires when this node stops reporting past the
 *     environment's inactive threshold (a node_inactive rule scoped to the
 *     node's UUID — only this node's transition fires it).
 *   - "Log match on this node": a result-log rule scoped to the node's
 *     UUID with an operator-supplied pattern, matching only this node's
 *     ingested results.
 *
 * Both rules are created with the environment resolved from the page
 * (rules are env-scoped; node_uuid pins the specific node). The modal
 * ends with the apply action so the rule goes live immediately — the
 * same hot-reload path as the Alerts page.
 */
export function NodeAlertModal({
  envID,
  envName,
  uuid,
  hostname,
  onClose,
}: {
  envID: number | undefined;
  envName: string;
  uuid: string;
  hostname: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<'inactive' | 'result'>('inactive');
  const [pattern, setPattern] = useState('');
  const [matchField, setMatchField] = useState('');
  const [cooldown, setCooldown] = useState(0);
  const [channelIDs, setChannelIDs] = useState<number[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const { data: channels } = useQuery({
    queryKey: ['alert-channels', 0],
    queryFn: () => listAlertChannels(),
    staleTime: 30_000,
  });

  const createMutation = useMutation({
    mutationFn: createAlertRule,
    onSuccess: () => {
      // Drop every cached rule list (all env filters) so the new rule is
      // there whether or not the operator goes on to apply it.
      void qc.invalidateQueries({ queryKey: ['alert-rules'] });
      setSaved(true);
    },
    onError: (e) => {
      if (e instanceof AuthError) return;
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const applyMutation = useMutation({
    mutationFn: () => applyAlerts(),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['alert-rules'] });
      onClose();
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : 'Reload failed');
    },
  });

  const inputClass = cn(
    'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
    'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
  );

  const baseName =
    kind === 'inactive' ? `${hostname}-inactive` : `${hostname}-log-match`;

  const submit = () => {
    setErr(null);
    if (envID === undefined) {
      setErr('Could not resolve the environment for this node');
      return;
    }
    if (kind === 'result' && !pattern.trim()) {
      setErr('A match pattern is required for log-match rules');
      return;
    }
    createMutation.mutate({
      name: baseName,
      environment_id: envID,
      source: kind === 'inactive' ? 'node_inactive' : 'result_log',
      node_uuid: uuid,
      match_type: kind === 'result' ? 'substring' : 'substring',
      match_field: kind === 'result' ? matchField : '',
      match_value: kind === 'result' ? pattern : '',
      cooldown_minutes: cooldown,
      channel_ids: channelIDs,
      enabled: true,
    });
  };

  if (saved) {
    return (
      <ModalShell
        title={`Alert created for ${hostname}`}
        titleId="node-alert-created-title"
        onClose={onClose}
      >
        <div className="space-y-4">
          <p className="text-sm text-[color:var(--text-2)]">
            Rule <span className="font-mono">{baseName}</span> was created for
            node <span className="font-mono">{uuid}</span> in{' '}
            <strong>{envName}</strong>. Apply the change so osctrl-tls picks
            it up without a restart.
          </p>
          {err && (
            <p role="alert" className="text-xs text-[color:var(--danger)]">
              {err}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              Apply later
            </Button>
            <Button
              type="button"
              disabled={applyMutation.isPending}
              onClick={() => applyMutation.mutate()}
            >
              {applyMutation.isPending ? 'Applying…' : 'Apply changes'}
            </Button>
          </div>
        </div>
      </ModalShell>
    );
  }

  return (
    <ModalShell
      title={`Alert on ${hostname}`}
      titleId="node-alert-modal-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-4"
      >
        <p className="text-xs text-[color:var(--text-3)]">
          Creates a rule scoped to node{' '}
          <span className="font-mono">{uuid}</span> in <strong>{envName}</strong>.
          Manage it later under Alerts.
        </p>

        {/* Rule kind */}
        <div role="radiogroup" aria-label="Alert type" className="space-y-2">
          <label
            className={cn(
              'flex items-start gap-2 rounded-md border px-3 py-2 cursor-pointer transition-colors',
              kind === 'inactive'
                ? 'border-[color:var(--signal)] bg-[color:var(--bg-3)]'
                : 'border-[color:var(--border)] hover:bg-[color:var(--bg-2)]',
            )}
          >
            <input
              type="radio"
              name="alert-kind"
              className="mt-0.5 accent-[color:var(--signal)]"
              checked={kind === 'inactive'}
              onChange={() => setKind('inactive')}
            />
            <span className="text-xs">
              <span className="block font-semibold text-[color:var(--text-1)]">
                Node goes inactive
              </span>
              <span className="text-[color:var(--text-3)]">
                Fires once when this node stops reporting past the
                environment&apos;s inactive threshold, and again on recovery
                if a recovery rule exists.
              </span>
            </span>
          </label>
          <label
            className={cn(
              'flex items-start gap-2 rounded-md border px-3 py-2 cursor-pointer transition-colors',
              kind === 'result'
                ? 'border-[color:var(--signal)] bg-[color:var(--bg-3)]'
                : 'border-[color:var(--border)] hover:bg-[color:var(--bg-2)]',
            )}
          >
            <input
              type="radio"
              name="alert-kind"
              className="mt-0.5 accent-[color:var(--signal)]"
              checked={kind === 'result'}
              onChange={() => setKind('result')}
            />
            <span className="text-xs">
              <span className="block font-semibold text-[color:var(--text-1)]">
                Log match on this node
              </span>
              <span className="text-[color:var(--text-3)]">
                Alerts when this node ingests a result-log row matching your
                pattern (case-insensitive substring).
              </span>
            </span>
          </label>
        </div>

        {kind === 'result' && (
          <>
            <div>
              <label
                htmlFor="node-alert-pattern"
                className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
              >
                Pattern <span className="text-[color:var(--danger)]">*</span>
              </label>
              <input
                id="node-alert-pattern"
                type="text"
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder="e.g. /etc/sudoers"
                className={cn(inputClass, 'font-mono')}
              />
            </div>
            <div>
              <label
                htmlFor="node-alert-field"
                className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
              >
                Field <span className="font-normal text-[color:var(--text-3)]">(empty = any)</span>
              </label>
              <input
                id="node-alert-field"
                type="text"
                value={matchField}
                onChange={(e) => setMatchField(e.target.value)}
                placeholder="e.g. path, username"
                className={inputClass}
              />
            </div>
          </>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label
              htmlFor="node-alert-cooldown"
              className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
            >
              Cooldown (minutes)
            </label>
            <input
              id="node-alert-cooldown"
              type="number"
              min={0}
              value={cooldown}
              onChange={(e) => setCooldown(Number(e.target.value))}
              className={inputClass}
            />
            <p className="mt-1 text-xs text-[color:var(--text-3)]">
              0 uses the default (15m).
            </p>
          </div>
        </div>

        {/* Channels */}
        <div>
          <span className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Channels
          </span>
          {(channels ?? []).length === 0 ? (
            <p className="text-xs text-[color:var(--text-3)]">
              No channels yet — the rule will match but nothing is sent. Create
              a channel under Admin → Alerts → Channels.
            </p>
          ) : (
            <div className="space-y-1">
              {(channels ?? []).map((c: AlertChannel) => (
                <label key={c.id} className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
                  <input
                    type="checkbox"
                    checked={channelIDs.includes(c.id)}
                    onChange={(e) => {
                      setChannelIDs((prev) =>
                        e.target.checked ? [...prev, c.id] : prev.filter((id) => id !== c.id),
                      );
                    }}
                    className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
                  />
                  <span className="tabular-nums">{c.name}</span>
                  <span className="text-[color:var(--text-3)]">({c.type})</span>
                </label>
              ))}
            </div>
          )}
        </div>

        {err && (
          <p role="alert" className="text-xs text-[color:var(--danger)]">
            {err}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={createMutation.isPending}>
            {createMutation.isPending ? 'Creating…' : 'Create alert'}
          </Button>
        </div>
      </form>
    </ModalShell>
  );
}
