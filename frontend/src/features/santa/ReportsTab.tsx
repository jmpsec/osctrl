import { useCallback, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { getSantaReport, santaQueryKey, SANTA_REPORT_DAYS, type SantaRankedBinary } from '$/api/santa';
import { Skeleton } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { BinaryModal } from './BinaryModal';
import { BINARY_LINK, MONO, ROW, TABLE, TD, TH, errorText } from './table';

const CARD = 'space-y-2 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4';
const SUB = 'text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]';

function Section({ title, hint, empty, children }: { title: string; hint: string; empty: boolean; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <section className={CARD}>
      <div>
        <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{title}</h2>
        <p className={SUB}>{hint}</p>
      </div>
      {empty ? <p className="text-sm text-[color:var(--text-3)]">{t('santa.reports.none')}</p> : <div className="overflow-x-auto">{children}</div>}
    </section>
  );
}

/** When an environment or a machine can move to LOCKDOWN, and which rules are missing. */
export function ReportsTab({ env }: { env: string }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const [days, setDays] = useState(14);
  const [binary, setBinary] = useState<string | null>(null);
  const closeBinary = useCallback(() => setBinary(null), []);
  const report = useQuery({
    queryKey: santaQueryKey(env, 'reports', days),
    queryFn: () => getSantaReport(env, days),
    placeholderData: (previous) => previous,
  });
  const r = report.data;
  const machines = r?.lockdown_ready ?? [];
  const ready = machines.filter((m) => m.ready).length;

  // Names and team IDs come from Santa clients: React text only.
  const binaries = (rows: SantaRankedBinary[]) => (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-[color:var(--border)]">
          <th scope="col" className={TH}>{t('santa.file')}</th>
          <th scope="col" className={`${TH} text-end`}>{t('santa.binary.executions')}</th>
          <th scope="col" className={`${TH} text-end`}>{t('santa.tabMachines')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((b) => (
          <tr key={b.sha256} className={ROW}>
            <td className={TD}>
              <button
                type="button"
                className={BINARY_LINK}
                aria-label={`${t('santa.binary.title')}: ${b.file_name || b.sha256}`}
                onClick={() => setBinary(b.sha256)}
              >
                {b.file_name || b.sha256}
              </button>
              <div className={`${MONO} ${SUB}`}>{b.sha256}</div>
              {b.team_id && <div className={`${MONO} ${SUB}`}>{b.team_id}</div>}
            </td>
            <td className={`${TD} text-end tabular-nums`}>{b.events}</td>
            <td className={`${TD} text-end tabular-nums`}>{b.machines}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <label htmlFor="santa-report-days" className="text-sm text-[color:var(--text-2)]">{t('santa.reports.window')}</label>
        <select
          id="santa-report-days"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
        >
          {SANTA_REPORT_DAYS.map((d) => <option key={d} value={d}>{t('santa.reports.days', { n: d })}</option>)}
        </select>
      </div>

      {report.isLoading ? (
        <Skeleton className="h-60 w-full" />
      ) : report.isError || !r ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(report.error) ?? t('santa.loadError')}</p>
      ) : (
        <>
          <Section title={t('santa.reports.lockdownTitle')} hint={t('santa.reports.lockdownHint')} empty={machines.length === 0}>
            <p role="status" className="mb-2 text-sm text-[color:var(--text-1)]">{t('santa.reports.readyCount', { n: ready, total: machines.length })}</p>
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)]">
                  <th scope="col" className={TH}>{t('santa.request.machine')}</th>
                  <th scope="col" className={TH}>{t('santa.lastSync')}</th>
                  <th scope="col" className={`${TH} text-end`}>{t('santa.reports.wouldBlock')}</th>
                  <th scope="col" className={TH}>{t('santa.request.status')}</th>
                </tr>
              </thead>
              <tbody>
                {machines.map((m) => (
                  <tr key={m.machine_id} className={ROW}>
                    <td className={TD}>
                      <div className="[overflow-wrap:anywhere]">{m.hostname || m.machine_id}</div>
                      {m.hostname && <div className={`${MONO} ${SUB}`}>{m.machine_id}</div>}
                    </td>
                    <td className={TD}>{m.last_sync_at ? formatDateTime(new Date(m.last_sync_at)) : t('santa.never')}</td>
                    <td className={`${TD} text-end tabular-nums`}>{m.would_block}</td>
                    <td className={TD}>
                      {m.ready
                        ? <span className="text-[color:var(--text-1)]">{t('santa.reports.ready')}</span>
                        : t(m.would_block > 0 ? 'santa.reports.notReady' : 'santa.reports.noRecentSync')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section title={t('santa.reports.gapsTitle')} hint={t('santa.reports.gapsHint')} empty={(r.coverage_gaps ?? []).length === 0}>
            {binaries(r.coverage_gaps ?? [])}
          </Section>

          <Section title={t('santa.reports.blockedTitle')} hint={t('santa.reports.blockedHint')} empty={(r.top_blocked ?? []).length === 0}>
            {binaries(r.top_blocked ?? [])}
          </Section>

          <Section title={t('santa.reports.teamsTitle')} hint={t('santa.reports.blockedHint')} empty={(r.top_blocked_teams ?? []).length === 0}>
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)]">
                  <th scope="col" className={TH}>Team ID</th>
                  <th scope="col" className={`${TH} text-end`}>{t('santa.binary.executions')}</th>
                  <th scope="col" className={`${TH} text-end`}>{t('santa.tabMachines')}</th>
                  <th scope="col" className={`${TH} text-end`}>{t('santa.reports.binaries')}</th>
                </tr>
              </thead>
              <tbody>
                {(r.top_blocked_teams ?? []).map((tm) => (
                  <tr key={tm.team_id} className={ROW}>
                    <td className={`${TD} ${MONO}`}>{tm.team_id}</td>
                    <td className={`${TD} text-end tabular-nums`}>{tm.events}</td>
                    <td className={`${TD} text-end tabular-nums`}>{tm.machines}</td>
                    <td className={`${TD} text-end tabular-nums`}>{tm.binaries}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          <p className={SUB}>{t('santa.reports.footnote')}</p>
        </>
      )}
      {binary && <BinaryModal env={env} sha256={binary} onClose={closeBinary} />}
    </div>
  );
}
