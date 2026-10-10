import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { VulnFinding } from '$/api/vulnerabilities';
import { StatusBadge } from '$/components/data/StatusBadge';
import { formatRelative } from '$/lib/time';
import { KevBadge, PossibleBadge, SeverityBadge } from './badges';

interface FindingsTableProps {
  env: string;
  findings: VulnFinding[];
  onOpenAdvisory: (advisoryId: string) => void;
  /** The node column is redundant on the node page itself. */
  showNode?: boolean;
}

const TH = 'px-4 py-2.5 text-start text-xs font-medium uppercase tracking-wide text-[color:var(--text-2)]';
const TD = 'px-4 py-2 text-xs';

export function FindingsTable({ env, findings, onOpenAdvisory, showNode = false }: FindingsTableProps) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
            <th scope="col" className={TH}>{t('vulns.colAdvisory')}</th>
            <th scope="col" className={TH}>{t('vulns.colPackage')}</th>
            <th scope="col" className={TH}>{t('vulns.colInstalled')}</th>
            <th scope="col" className={TH}>{t('vulns.colFixed')}</th>
            <th scope="col" className={TH}>{t('vulns.colSeverity')}</th>
            {showNode && <th scope="col" className={TH}>{t('vulns.colNode')}</th>}
            <th scope="col" className={TH}>{t('vulns.colFirstSeen')}</th>
          </tr>
        </thead>
        <tbody>
          {/* Possible (NVD name) matches stay visible but recede: they may be false positives. */}
          {findings.map((f) => (
            <tr
              key={f.id}
              className={`border-b border-[color:var(--border)] align-top last:border-0${f.confidence === 'possible' ? ' opacity-70' : ''}`}
            >
              <td className={TD}>
                <button
                  type="button"
                  onClick={() => onOpenAdvisory(f.advisory_id)}
                  className="font-mono text-[color:var(--text-link)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]"
                >
                  {f.advisory_id}
                </button>
              </td>
              <td className={TD}>
                <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{f.package}</div>
                <div className="text-[color:var(--text-3)]">{f.ecosystem}</div>
              </td>
              <td className={`${TD} font-mono text-[color:var(--text-2)] [overflow-wrap:anywhere]`}>{f.installed_version}</td>
              <td className={`${TD} font-mono [overflow-wrap:anywhere]`}>
                {f.fixed_version || <span className="font-sans text-[color:var(--text-3)]">{t('vulns.noFix')}</span>}
              </td>
              <td className={TD}>
                <div className="flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={f.severity} />
                  {f.kev && <KevBadge />}
                  {f.confidence === 'possible' && <PossibleBadge />}
                  {f.resolved_at && <StatusBadge variant="success" label={t('vulns.stateResolved')} />}
                </div>
              </td>
              {showNode && (
                <td className={TD}>
                  <Link
                    to="/_app/env/$env/nodes/$uuid"
                    params={{ env, uuid: f.node_uuid }}
                    title={f.node_uuid}
                    className="font-mono text-[color:var(--text-link)] hover:underline"
                  >
                    {f.node_uuid.slice(0, 8)}
                  </Link>
                </td>
              )}
              <td className={`${TD} whitespace-nowrap text-[color:var(--text-3)]`}>
                <span title={f.first_seen}>{formatRelative(f.first_seen)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
