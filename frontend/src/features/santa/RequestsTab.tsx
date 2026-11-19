import { useCallback, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import {
  decideSantaRequest,
  listSantaMachines,
  listSantaRequests,
  santaQueryKey,
  type SantaDecision,
  type SantaRequest,
  type SantaRequestStatus,
  type SantaScope,
} from '$/api/santa';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { EmptyState } from '$/components/data/EmptyState';
import { SkeletonRow } from '$/components/data/Skeleton';
import { ModalShell } from '$/components/feedback/ModalShell';
import { useLocale } from '$/i18n/useLocale';
import { BinaryModal } from './BinaryModal';
import { RiskBadge } from './RiskBadge';
import { BINARY_LINK, MONO, ROW, TABLE, TD, TH, errorText } from './table';

const STATUSES: SantaRequestStatus[] = ['pending', 'approved', 'denied', 'expired'];
const MAX_REASON = 1000;
const SELECT =
  'h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]';

interface Pending {
  approve: boolean;
  ids: number[];
  /** Every request is for MONITOR mode, so there is no rule scope to choose. */
  monitor: boolean;
  /** A risk check flagged at least one of the files. */
  flagged: boolean;
}

/** What a request asks for, as one line: the file, or MONITOR mode. */
export function requestName(r: SantaRequest, t: (key: string, o?: Record<string, unknown>) => string): string {
  return r.kind === 'monitor' ? t('santa.monitor.name', { n: r.monitor_hours }) : r.file_name || r.file_sha256;
}

/**
 * The approval queue: requests from blocked users, decided one at a time or in bulk.
 * Approvers who are not environment admins (admin false) get no machine names or binary details.
 */
export function RequestsTab({ env, admin = true }: { env: string; admin?: boolean }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const [status, setStatus] = useState<SantaRequestStatus | ''>('pending');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [dialog, setDialog] = useState<Pending | null>(null);
  const [binary, setBinary] = useState<string | null>(null);
  const closeBinary = useCallback(() => setBinary(null), []);
  const closeDialog = useCallback(() => {
    setDialog(null);
    setSelected(new Set());
  }, []);
  const requests = useQuery({ queryKey: santaQueryKey(env, 'requests', status), queryFn: () => listSantaRequests(env, status) });
  const machines = useQuery({ queryKey: santaQueryKey(env, 'machines'), queryFn: () => listSantaMachines(env), enabled: admin });
  const hostnames = useMemo(() => new Map((machines.data ?? []).map((m) => [m.machine_id, m.hostname])), [machines.data]);

  // The API returns at most 500 requests, so searching them here is enough.
  const needle = search.trim().toLowerCase();
  const rows = (requests.data ?? []).filter(
    (r) =>
      needle === '' ||
      [r.file_name, r.file_path, r.file_sha256, r.machine_id, hostnames.get(r.machine_id) ?? '', r.requester, r.justification]
        .some((v) => v.toLowerCase().includes(needle)),
  );
  const pending = rows.filter((r) => r.status === 'pending');
  const chosenRows = pending.filter((r) => selected.has(r.id));
  const chosen = chosenRows.map((r) => r.id);
  const allMonitor = chosenRows.every((r) => r.kind === 'monitor');
  const anyFlagged = chosenRows.some((r) => r.risk?.verdict === 'flagged');
  const toggle = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          type="search"
          aria-label={t('santa.requests.search')}
          placeholder={t('santa.requests.search')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <select
          aria-label={t('santa.request.status')}
          className={SELECT}
          value={status}
          onChange={(e) => {
            setStatus(e.target.value as SantaRequestStatus | '');
            setSelected(new Set());
          }}
        >
          <option value="">{t('santa.requests.all')}</option>
          {STATUSES.map((s) => <option key={s} value={s}>{t(`santa.request.statuses.${s}`)}</option>)}
        </select>
        <div className="ms-auto flex gap-2">
          <Button size="sm" disabled={chosen.length === 0} onClick={() => setDialog({ approve: true, ids: chosen, monitor: allMonitor, flagged: anyFlagged })}>
            {t('santa.requests.approve')} ({chosen.length})
          </Button>
          <Button size="sm" variant="danger" disabled={chosen.length === 0} onClick={() => setDialog({ approve: false, ids: chosen, monitor: allMonitor, flagged: anyFlagged })}>
            {t('santa.requests.deny')} ({chosen.length})
          </Button>
        </div>
      </div>
      <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
        {requests.isLoading ? (
          <table className={TABLE}><tbody>{Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}</tbody></table>
        ) : requests.isError ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.loadError')} description={errorText(requests.error)} />
        ) : rows.length === 0 ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.requests.none')} />
        ) : (
          <div className="overflow-x-auto">
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                  <th scope="col" className={TH}>
                    <input
                      type="checkbox"
                      aria-label={t('santa.requests.selectAll')}
                      disabled={pending.length === 0}
                      checked={pending.length > 0 && chosen.length === pending.length}
                      onChange={(e) => setSelected(new Set(e.target.checked ? pending.map((r) => r.id) : []))}
                    />
                  </th>
                  <th scope="col" className={TH}>{t('santa.file')}</th>
                  <th scope="col" className={TH}>{t('santa.request.machine')}</th>
                  <th scope="col" className={TH}>{t('santa.requests.requester')}</th>
                  <th scope="col" className={TH}>{t('santa.request.status')}</th>
                  <th scope="col" className={TH}><span className="sr-only">{t('santa.actions')}</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <RequestRow
                    key={r.id}
                    r={r}
                    hostname={hostnames.get(r.machine_id)}
                    when={formatDateTime(new Date(r.created_at))}
                    selected={selected.has(r.id)}
                    onToggle={() => toggle(r.id)}
                    onBinary={admin ? () => setBinary(r.file_sha256) : undefined}
                    onDecide={(approve) => setDialog({ approve, ids: [r.id], monitor: r.kind === 'monitor', flagged: r.risk?.verdict === 'flagged' })}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {dialog && <DecisionModal env={env} pending={dialog} onClose={closeDialog} />}
      {binary && <BinaryModal env={env} sha256={binary} onClose={closeBinary} />}
    </div>
  );
}

function RequestRow({
  r,
  hostname,
  when,
  selected,
  onToggle,
  onDecide,
  onBinary,
}: {
  r: SantaRequest;
  hostname?: string;
  when: string;
  selected: boolean;
  onToggle: () => void;
  /** Opens the binary details; without it the name is plain text. */
  onBinary?: () => void;
  onDecide: (approve: boolean) => void;
}) {
  const { t } = useTranslation();
  const name = requestName(r, t);
  const sub = 'text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]';
  return (
    <tr className={ROW}>
      <td className={TD}>
        {r.status === 'pending' && <input type="checkbox" aria-label={name} checked={selected} onChange={onToggle} />}
      </td>
      {/* File names, paths, signing IDs and the justification come from clients and users: React text only. */}
      <td className={TD}>
        {r.file_sha256 && onBinary ? (
          <button type="button" className={BINARY_LINK} aria-label={`${t('santa.binary.title')}: ${name}`} onClick={onBinary}>{name}</button>
        ) : (
          <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{name}</div>
        )}
        {r.file_path && <div className={sub}>{r.file_path}</div>}
        {r.file_sha256 && <div className={`${MONO} ${sub}`}>{r.file_sha256}</div>}
        {r.risk && <div className="mt-1"><RiskBadge risk={r.risk} /></div>}
        {r.risk_override && <div className={sub}>{t('santa.risk.overridden')}</div>}
        {r.signing_id && <div className={`${MONO} ${sub}`}>{r.signing_id}</div>}
      </td>
      <td className={TD}>
        <div className="[overflow-wrap:anywhere]">{hostname || r.machine_id}</div>
        {hostname && <div className={`${MONO} ${sub}`}>{r.machine_id}</div>}
        {r.executing_user && <div className={sub}>{r.executing_user}</div>}
      </td>
      <td className={TD}>
        <div className="text-[color:var(--text-1)]">{r.requester}</div>
        <div className={sub}>{r.justification}</div>
        <div className={sub}>{when}</div>
      </td>
      <td className={TD}>
        {t(`santa.request.statuses.${r.status}`)}
        {r.decided_by && <div className={sub}>{r.decided_by}</div>}
        {r.reason && <div className={sub}>{r.reason}</div>}
      </td>
      <td className={`${TD} whitespace-nowrap text-end`}>
        {r.status === 'pending' && (
          <div className="flex justify-end gap-1.5">
            <Button size="sm" aria-label={`${t('santa.requests.approve')} ${name}`} onClick={() => onDecide(true)}>
              {t('santa.requests.approve')}
            </Button>
            <Button size="sm" variant="danger" aria-label={`${t('santa.requests.deny')} ${name}`} onClick={() => onDecide(false)}>
              {t('santa.requests.deny')}
            </Button>
          </div>
        )}
      </td>
    </tr>
  );
}

function DecisionModal({
  env,
  pending,
  onClose,
}: {
  env: string;
  pending: Pending;
  /** Must be stable (useCallback): ModalShell re-runs its focus effect on change. */
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { approve, ids, monitor, flagged } = pending;
  const decide = useMutation({
    // One call per request, so one failure does not undo the others.
    mutationFn: async (body: SantaDecision) => {
      const failures: unknown[] = [];
      for (const id of ids) {
        try {
          await decideSantaRequest(env, id, body);
        } catch (e) {
          failures.push(e);
        }
      }
      await Promise.all([
        qc.invalidateQueries({ queryKey: santaQueryKey(env, 'requests') }),
        qc.invalidateQueries({ queryKey: santaQueryKey(env, 'rules') }),
        qc.invalidateQueries({ queryKey: santaQueryKey(env, 'modes') }),
      ]);
      if (failures.length > 0) throw new Error(`${failures.length}/${ids.length}: ${errorText(failures[0]) ?? ''}`);
    },
    onSuccess: onClose,
  });

  return (
    <ModalShell
      title={t(approve ? 'santa.requests.approveTitle' : 'santa.requests.denyTitle', { n: ids.length })}
      titleId="santa-decision-title"
      onClose={onClose}
    >
      <DecisionForm approve={approve} monitor={monitor} flagged={flagged} pending={decide.isPending} error={errorText(decide.error)} onSubmit={decide.mutate} onCancel={onClose} />
    </ModalShell>
  );
}

/** The approver's choices: where the allow rule applies, and the reason. Shared by the queue and the notification links. */
export function DecisionForm({
  approve,
  monitor = false,
  flagged = false,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  approve: boolean;
  /** Approving MONITOR mode: no rule scope, the hours were asked for. */
  monitor?: boolean;
  /** A risk check flagged the file: approving needs an explicit, reasoned override. */
  flagged?: boolean;
  pending: boolean;
  error?: string;
  onSubmit: (body: SantaDecision) => void;
  onCancel?: () => void;
}) {
  const { t } = useTranslation();
  const [scope, setScope] = useState<SantaScope>('node');
  const [tag, setTag] = useState('');
  const [reason, setReason] = useState('');
  const [override, setOverride] = useState(false);
  const needsOverride = approve && flagged;
  const reasonRequired = !approve || (needsOverride && override);

  function submit(e: FormEvent) {
    e.preventDefault();
    onSubmit(
      approve
        ? { decision: 'approve', scope, scope_value: scope === 'tag' ? tag : '', reason, ...(needsOverride && override ? { override: true } : {}) }
        : { decision: 'deny', reason },
    );
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      {approve && monitor && <p className="text-sm text-[color:var(--text-2)]">{t('santa.monitor.approveHint')}</p>}
      {approve && !monitor && (
        <>
          <p className="text-sm text-[color:var(--text-2)]">{t('santa.requests.approveHint')}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="santa-decision-scope">{t('santa.scope')}</Label>
              <select id="santa-decision-scope" className={`${SELECT} w-full`} value={scope} onChange={(e) => setScope(e.target.value as SantaScope)}>
                <option value="node">{t('santa.requests.thisMachine')}</option>
                <option value="tag">{t('santa.scopes.tag')}</option>
                <option value="env">{t('santa.scopes.env')}</option>
              </select>
            </div>
            {scope === 'tag' && (
              <div>
                <Label htmlFor="santa-decision-tag" required>{t('santa.scopes.tag')}</Label>
                <Input id="santa-decision-tag" required value={tag} onChange={(e) => setTag(e.target.value.trim())} />
              </div>
            )}
          </div>
        </>
      )}
      {needsOverride && (
        <div role="alert" className="space-y-2 rounded-md border border-[color:var(--danger)] p-3">
          <p className="text-sm text-[color:var(--danger)]">{t('santa.risk.flaggedWarning')}</p>
          <label className="flex items-center gap-2 text-sm text-[color:var(--text-1)]">
            <input type="checkbox" checked={override} onChange={(e) => setOverride(e.target.checked)} />
            {t('santa.risk.override')}
          </label>
        </div>
      )}
      <div>
        <Label htmlFor="santa-decision-reason" required={reasonRequired}>{t('santa.requests.reason')}</Label>
        <textarea
          id="santa-decision-reason"
          required={reasonRequired}
          rows={3}
          maxLength={MAX_REASON}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] p-2 text-sm text-[color:var(--text-1)]"
        />
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.requests.reasonHint')}</p>
      </div>
      {error && <p role="alert" className="text-sm text-[color:var(--danger)]">{error}</p>}
      <div className="flex justify-end gap-2">
        {onCancel && <Button type="button" variant="ghost" onClick={onCancel}>{t('common.cancel')}</Button>}
        <Button
          type="submit"
          variant={approve ? undefined : 'danger'}
          disabled={pending || (needsOverride && !override) || (reasonRequired && reason.trim() === '')}
        >
          {t(approve ? 'santa.requests.approve' : 'santa.requests.deny')}
        </Button>
      </div>
    </form>
  );
}
