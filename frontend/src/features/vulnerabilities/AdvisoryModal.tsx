import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getVulnAdvisory, type VulnAdvisoryDetail } from '$/api/vulnerabilities';
import { ModalShell } from '$/components/feedback/ModalShell';
import { MetadataBadge } from '$/components/data/MetadataBadge';
import { Skeleton } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { KevBadge, SeverityBadge } from './badges';
import { ADVISORY_FINDINGS_LIMIT, safeExternalUrl } from './vulnFormat';

interface AdvisoryModalProps {
  env: string;
  advisoryId: string;
  /** Must be stable (useCallback): ModalShell re-runs its focus effect on change. */
  onClose: () => void;
}

/**
 * One advisory and the nodes it affects in this environment.
 *
 * Advisory text and links come from external feeds. Everything renders as
 * React text, which is escaped, and only https URLs become links.
 */
export function AdvisoryModal({ env, advisoryId, onClose }: AdvisoryModalProps) {
  const { t } = useTranslation();
  const { data, isLoading, error } = useQuery({
    queryKey: ['vuln-advisory', env, advisoryId],
    queryFn: () => getVulnAdvisory(env, advisoryId),
    staleTime: 60_000,
  });
  const notFound = (error as { status?: number } | null)?.status === 404;
  return (
    <ModalShell
      title={advisoryId}
      titleId="vuln-advisory-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      {isLoading && <Skeleton className="h-24 w-full" />}
      {error && (
        <p role="alert" className="text-sm text-[color:var(--danger)]">
          {notFound ? t('vulns.advisoryNotFound') : t('vulns.loadError')}
        </p>
      )}
      {data && <AdvisoryBody env={env} detail={data} onNavigate={onClose} />}
    </ModalShell>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-[color:var(--text-3)]">{title}</h3>
      {children}
    </section>
  );
}

/** onNavigate closes the dialog when a node link is followed: on the node
 * tab the page is not remounted, so an open dialog would hide the move. */
function AdvisoryBody({ env, detail, onNavigate }: { env: string; detail: VulnAdvisoryDetail; onNavigate: () => void }) {
  const { t } = useTranslation();
  const { formatNumber } = useLocale();
  const { advisory, aliases, references, findings } = detail;
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={advisory.severity} />
        {advisory.kev && <KevBadge />}
        {advisory.cvss_score > 0 && (
          <MetadataBadge title={advisory.cvss_vector}>
            {`CVSS ${formatNumber(advisory.cvss_score, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}`}
          </MetadataBadge>
        )}
      </div>
      {advisory.summary && (
        <p className="font-medium text-[color:var(--text-1)] [overflow-wrap:anywhere]">{advisory.summary}</p>
      )}
      {advisory.details && (
        <p className="whitespace-pre-wrap text-xs leading-relaxed text-[color:var(--text-2)] [overflow-wrap:anywhere]">
          {advisory.details}
        </p>
      )}
      {aliases.length > 0 && (
        <Section title={t('vulns.aliases')}>
          <div className="flex flex-wrap gap-1">
            {aliases.map((alias) => <MetadataBadge key={alias}>{alias}</MetadataBadge>)}
          </div>
        </Section>
      )}
      {references.length > 0 && (
        <Section title={t('vulns.references')}>
          <ul className="space-y-1 text-xs">
            {references.map((ref, i) => {
              const href = safeExternalUrl(ref);
              return (
                <li key={`${i}-${ref}`} className="[overflow-wrap:anywhere]">
                  {href ? (
                    <a href={href} target="_blank" rel="noopener noreferrer" className="text-[color:var(--text-link)] hover:underline">
                      {ref}
                    </a>
                  ) : (
                    <span className="text-[color:var(--text-3)]">{ref}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      )}
      <Section title={t('vulns.affectedHere')}>
        {findings.length === 0 ? (
          <p className="text-xs text-[color:var(--text-3)]">—</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2">
                <Link
                  to="/_app/env/$env/nodes/$uuid"
                  params={{ env, uuid: f.node_uuid }}
                  title={f.node_uuid}
                  onClick={onNavigate}
                  className="font-mono text-[color:var(--text-link)] hover:underline"
                >
                  {f.node_uuid.slice(0, 8)}
                </Link>
                <span className="text-[color:var(--text-2)]">{f.package} {f.installed_version}</span>
                <span className="text-[color:var(--text-3)]">→ {f.fixed_version || t('vulns.noFix')}</span>
              </li>
            ))}
          </ul>
        )}
        {findings.length >= ADVISORY_FINDINGS_LIMIT && (
          <p role="status" className="text-xs text-[color:var(--warning)]">
            {t('vulns.truncated', { count: formatNumber(ADVISORY_FINDINGS_LIMIT) })}
          </p>
        )}
      </Section>
    </div>
  );
}
