import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createSantaRequest, getSantaVotes, listMySantaRequests, SANTA_MONITOR_HOURS, voteSantaFile } from '$/api/santa';
import { Button } from '$/components/atoms/Button';
import { Label } from '$/components/atoms/Label';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

const MAX_JUSTIFICATION = 1000;

/**
 * Voting for the file, shown only when the environment has a vote threshold.
 * It shows counts, never who voted.
 */
function VoteCard({ env, sha256, machineId }: { env: string; sha256: string; machineId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = ['santa', env, 'votes', sha256];
  const votes = useQuery({ queryKey: key, queryFn: () => getSantaVotes(env, sha256), retry: false });
  const cast = useMutation({
    mutationFn: () => voteSantaFile(env, { sha256, machine_id: machineId }),
    onSuccess: (st) => qc.setQueryData(key, st),
  });
  const st = votes.data;
  if (!st || (st.local_threshold === 0 && st.global_threshold === 0)) return null;
  return (
    <section className="space-y-2 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4">
      <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.vote.title')}</h2>
      <p className="text-sm text-[color:var(--text-2)]">
        {t('santa.vote.count', { n: st.votes })}
        {st.local_threshold > 0 && ` ${t('santa.vote.local', { n: st.local_threshold })}`}
        {st.global_threshold > 0 && ` ${t('santa.vote.global', { n: st.global_threshold })}`}
      </p>
      {st.allowed !== '' && (
        <p role="status" className="text-sm text-[color:var(--text-1)]">
          {t(st.allowed === 'env' ? 'santa.vote.allowedEnv' : 'santa.vote.allowedNode')}
        </p>
      )}
      {cast.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(cast.error)}</p>}
      <div className="flex justify-end">
        <Button type="button" disabled={st.voted || cast.isPending} onClick={() => cast.mutate()}>
          {t(st.voted ? 'santa.vote.voted' : 'santa.vote.button')}
        </Button>
      </div>
    </section>
  );
}

/** Asking for temporary MONITOR mode on the machine, through the same approval queue. */
function MonitorCard({ env, machineId, onSent }: { env: string; machineId: string; onSent: () => void }) {
  const { t } = useTranslation();
  const [hours, setHours] = useState(SANTA_MONITOR_HOURS[0]);
  const [justification, setJustification] = useState('');
  const send = useMutation({
    mutationFn: () => createSantaRequest(env, { kind: 'monitor', machine_id: machineId, hours, justification }),
    onSuccess: onSent,
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    send.mutate();
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4">
      <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.monitor.title')}</h2>
      <p className="text-sm text-[color:var(--text-2)]">{t('santa.monitor.intro')}</p>
      {send.isSuccess ? (
        <p role="status" className="text-sm text-[color:var(--text-1)]">
          {t('santa.request.status')}: {t(`santa.request.statuses.${send.data.status}`)}
        </p>
      ) : (
        <>
          <div>
            <Label htmlFor="santa-monitor-hours">{t('santa.monitor.duration')}</Label>
            <select
              id="santa-monitor-hours"
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
            >
              {SANTA_MONITOR_HOURS.map((h) => <option key={h} value={h}>{t('santa.monitor.hours', { n: h })}</option>)}
            </select>
          </div>
          <div>
            <Label htmlFor="santa-monitor-why" required>{t('santa.request.justification')}</Label>
            <textarea
              id="santa-monitor-why"
              required
              rows={3}
              maxLength={MAX_JUSTIFICATION}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] p-2 text-sm text-[color:var(--text-1)]"
            />
          </div>
          {send.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(send.error)}</p>}
          <div className="flex justify-end">
            <Button type="submit" variant="ghost" disabled={send.isPending || justification.trim() === ''}>{t('santa.monitor.submit')}</Button>
          </div>
        </>
      )}
    </form>
  );
}

/**
 * The page a blocked user lands on from the Santa dialog. It shows only what
 * the link carried and the user's own requests.
 */
export function RequestPage({ env, sha256, machineId }: { env: string; sha256: string; machineId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [justification, setJustification] = useState('');
  const mineKey = ['santa', env, 'requests', 'mine'];
  const mine = useQuery({ queryKey: mineKey, queryFn: () => listMySantaRequests(env), retry: false });
  const send = useMutation({
    mutationFn: () => createSantaRequest(env, { sha256, machine_id: machineId, justification }),
    onSuccess: () => qc.invalidateQueries({ queryKey: mineKey }),
  });
  const complete = sha256 !== '' && machineId !== '';

  function submit(e: FormEvent) {
    e.preventDefault();
    send.mutate();
  }

  return (
    <main className="mx-auto min-h-screen max-w-2xl space-y-4 bg-[color:var(--bg-0)] p-4 sm:p-8">
      <h1 className="text-lg font-semibold text-[color:var(--text-1)]">{t('santa.request.title')}</h1>
      {!complete ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{t('santa.request.incomplete')}</p>
      ) : (
        <form onSubmit={submit} className="space-y-3 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4">
          <p className="text-sm text-[color:var(--text-2)]">{t('santa.request.intro')}</p>
          <dl className="space-y-2 text-sm">
            <div>
              <dt className="text-xs text-[color:var(--text-3)]">{t('santa.request.file')}</dt>
              <dd className={`${MONO} text-[color:var(--text-1)]`}>{sha256}</dd>
            </div>
            <div>
              <dt className="text-xs text-[color:var(--text-3)]">{t('santa.request.machine')}</dt>
              <dd className={`${MONO} text-[color:var(--text-1)]`}>{machineId}</dd>
            </div>
          </dl>
          {send.isSuccess ? (
            <p role="status" className="text-sm text-[color:var(--text-1)]">
              {send.data.justification ? t('santa.request.submitted') : t('santa.request.alreadyRequested')}{' '}
              {t('santa.request.status')}: {t(`santa.request.statuses.${send.data.status}`)}
            </p>
          ) : (
            <>
              <div>
                <Label htmlFor="santa-request-why" required>{t('santa.request.justification')}</Label>
                <textarea
                  id="santa-request-why"
                  required
                  rows={4}
                  maxLength={MAX_JUSTIFICATION}
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  className="w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] p-2 text-sm text-[color:var(--text-1)]"
                />
              </div>
              {send.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(send.error)}</p>}
              <div className="flex justify-end">
                <Button type="submit" disabled={send.isPending || justification.trim() === ''}>{t('santa.request.submit')}</Button>
              </div>
            </>
          )}
        </form>
      )}
      {complete && <VoteCard env={env} sha256={sha256} machineId={machineId} />}
      {complete && <MonitorCard env={env} machineId={machineId} onSent={() => qc.invalidateQueries({ queryKey: mineKey })} />}
      {mine.data && mine.data.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.request.mine')}</h2>
          <div className="overflow-x-auto">
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)]">
                  <th scope="col" className={TH}>{t('santa.request.file')}</th>
                  <th scope="col" className={TH}>{t('santa.request.status')}</th>
                  <th scope="col" className={TH}>{t('santa.request.requested')}</th>
                </tr>
              </thead>
              <tbody>
                {mine.data.map((r) => (
                  <tr key={r.id} className={ROW}>
                    {r.kind === 'monitor' ? (
                      <td className={TD}>{t('santa.monitor.name', { n: r.monitor_hours })}</td>
                    ) : (
                      <td className={`${TD} ${MONO}`}>{r.file_sha256}</td>
                    )}
                    <td className={TD}>
                      {t(`santa.request.statuses.${r.status}`)}
                      {r.reason && <div className="text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]">{r.reason}</div>}
                    </td>
                    <td className={TD}>{new Date(r.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}
