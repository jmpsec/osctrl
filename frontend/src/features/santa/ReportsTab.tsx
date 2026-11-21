import { useCallback, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getSantaReport, getSantaReportCSVUrl, santaQueryKey, setSantaModeOverride, SANTA_REPORT_DAYS, type SantaRankedBinary, type SantaReport,
} from '$/api/santa';
import { Button } from '$/components/atoms/Button';
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

/** Downloads the report as it is shown, as JSON. */
function exportJSON(env: string, report: SantaReport) {
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `santa-report-${env}-${report.days}d.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
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
  const trend = r?.trend ?? [];
  const trendMax = Math.max(1, ...trend.map((d) => d.blocked), ...trend.map((d) => d.would_block_machines));
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string[]>([]);
  // Each machine gets a permanent node override through the audited mode override route.
  const lockdown = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => setSantaModeOverride(env, { scope: 'node', scope_value: id, client_mode: 'LOCKDOWN' })),
      );
      return {
        done: results.filter((x) => x.status === 'fulfilled').length,
        failed: results.flatMap((x, i) => (x.status === 'rejected' ? [`${ids[i]}: ${errorText(x.reason) ?? ''}`] : [])),
      };
    },
    onSettled: () => {
      setSelected([]);
      for (const part of ['reports', 'modes', 'machines'] as const) void qc.invalidateQueries({ queryKey: santaQueryKey(env, part) });
    },
  });
  const toggle = (id: string, on: boolean) => setSelected((s) => (on ? [...s, id] : s.filter((x) => x !== id)));

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
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="santa-report-days" className="text-sm text-[color:var(--text-2)]">{t('santa.reports.window')}</label>
        <select
          id="santa-report-days"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
        >
          {SANTA_REPORT_DAYS.map((d) => <option key={d} value={d}>{t('santa.reports.days', { n: d })}</option>)}
        </select>
        <a
          href={getSantaReportCSVUrl(env, days)}
          download
          className="ms-auto inline-flex h-8 items-center rounded-md px-3 text-sm text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)]"
        >
          {t('santa.reports.exportCsv')}
        </a>
        <Button size="sm" variant="ghost" disabled={!r} onClick={() => r && exportJSON(env, r)}>{t('santa.reports.exportJson')}</Button>
      </div>

      {report.isLoading ? (
        <Skeleton className="h-60 w-full" />
      ) : report.isError || !r ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(report.error) ?? t('santa.loadError')}</p>
      ) : (
        <>
          <Section title={t('santa.reports.lockdownTitle')} hint={t('santa.reports.lockdownHint')} empty={machines.length === 0}>
            <p role="status" className="mb-2 text-sm text-[color:var(--text-1)]">{t('santa.reports.readyCount', { n: ready, total: machines.length })}</p>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                variant="ghost"
                disabled={ready === 0}
                onClick={() => setSelected(machines.filter((m) => m.ready).map((m) => m.machine_id))}
              >
                {t('santa.reports.selectReady')}
              </Button>
              <Button
                size="sm"
                disabled={selected.length === 0 || lockdown.isPending}
                onClick={() => {
                  if (confirm(t('santa.reports.confirmLockdown', { n: selected.length }))) lockdown.mutate(selected);
                }}
              >
                {t('santa.reports.applyLockdown', { n: selected.length })}
              </Button>
            </div>
            {lockdown.data && (
              <p role="status" className="mb-2 text-sm text-[color:var(--text-1)]">
                {t('santa.reports.lockdownDone', { n: lockdown.data.done })}
                {lockdown.data.failed.length > 0 && (
                  <span className="block text-[color:var(--danger)]">{t('santa.reports.lockdownFailed', { n: lockdown.data.failed.length, errors: lockdown.data.failed.join('; ') })}</span>
                )}
              </p>
            )}
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)]">
                  <th scope="col" className={TH}><span className="sr-only">{t('santa.reports.select')}</span></th>
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
                      {m.ready && (
                        <input
                          type="checkbox"
                          aria-label={`${t('santa.reports.select')} ${m.hostname || m.machine_id}`}
                          checked={selected.includes(m.machine_id)}
                          onChange={(e) => toggle(m.machine_id, e.target.checked)}
                        />
                      )}
                    </td>
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

          <Section title={t('santa.reports.trendTitle')} hint={t('santa.reports.trendHint')} empty={trend.every((d) => d.blocked === 0 && d.would_block === 0)}>
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)]">
                  <th scope="col" className={TH}>{t('santa.reports.day')}</th>
                  <th scope="col" className={TH}>{t('santa.binary.blocked')}</th>
                  <th scope="col" className={TH}>{t('santa.reports.wouldBlockMachines')}</th>
                </tr>
              </thead>
              <tbody>
                {trend.map((d) => (
                  <tr key={d.day} className={ROW}>
                    <td className={`${TD} whitespace-nowrap`}>{d.day.slice(0, 10)}</td>
                    {[d.blocked, d.would_block_machines].map((n, i) => (
                      <td key={i} className={TD}>
                        <div className="flex items-center gap-2">
                          <div
                            aria-hidden="true"
                            className={`h-2 rounded ${i === 0 ? 'bg-[color:var(--danger)]' : 'bg-[color:var(--warning)]'}`}
                            style={{ width: `${(n / trendMax) * 8}rem` }}
                          />
                          <span className="tabular-nums">{n}</span>
                        </div>
                      </td>
                    ))}
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
