import { useTranslation } from 'react-i18next';
import type { SantaRisk } from '$/api/santa';

const TONE: Record<SantaRisk['verdict'], string> = {
  flagged: 'border-[color:var(--danger)] text-[color:var(--danger)]',
  error: 'border-[color:var(--warning)] text-[color:var(--text-1)]',
  clean: 'border-[color:var(--border)] text-[color:var(--text-2)]',
  unknown: 'border-[color:var(--border)] text-[color:var(--text-3)]',
  unchecked: 'border-[color:var(--border)] text-[color:var(--text-3)]',
};

/**
 * The aggregated risk verdict of a file, with each check's detail as the
 * title. Details come from third-party services: React text only.
 */
export function RiskBadge({ risk }: { risk?: SantaRisk }) {
  const { t } = useTranslation();
  if (!risk) return null;
  const detail = (risk.checks ?? []).map((c) => `${c.check}: ${c.detail || c.verdict}`).join('\n');
  return (
    <span
      title={detail || undefined}
      className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${TONE[risk.verdict]}`}
    >
      {t(`santa.risk.verdicts.${risk.verdict}`)}
    </span>
  );
}
