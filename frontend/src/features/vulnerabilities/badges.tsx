import { useTranslation } from 'react-i18next';
import { StatusBadge } from '$/components/data/StatusBadge';
import type { VulnSeverity } from '$/api/vulnerabilities';
import { severityVariant } from './vulnFormat';

export function SeverityBadge({ severity }: { severity: VulnSeverity }) {
  const { t } = useTranslation();
  return <StatusBadge variant={severityVariant(severity)} label={t(`vulns.severity.${severity}`)} />;
}

/** CISA KEV: exploited in the wild, so it outranks the CVSS severity. */
export function KevBadge() {
  const { t } = useTranslation();
  return (
    <span className="rounded border border-[color:var(--danger)]/40 bg-[color:var(--danger)]/10 px-1.5 py-0.5 text-[11px] font-semibold text-[color:var(--danger)]">
      {t('vulns.kev')}
    </span>
  );
}

/** A name-and-version heuristic match (NVD CPE). Shown, never alerted on. */
export function PossibleBadge() {
  const { t } = useTranslation();
  return (
    <span title={t('vulns.possibleHint')}>
      <StatusBadge variant="dim" label={t('vulns.confidence.possible')} />
    </span>
  );
}
