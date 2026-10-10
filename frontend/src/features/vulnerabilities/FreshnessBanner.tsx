import { useTranslation } from 'react-i18next';
import { cn } from '$/lib/cn';

/**
 * Before the first sync, or while a feed is failing, the absence of findings
 * proves nothing. Say so wherever findings are listed.
 */
export function FreshnessBanner({ loaded, stale }: { loaded: boolean; stale: boolean }) {
  const { t } = useTranslation();
  if (loaded && !stale) return null;
  return (
    <div
      role="status"
      className={cn(
        'rounded-lg border px-4 py-3 text-sm',
        !loaded
          ? 'border-[color:var(--info)]/30 bg-[color:var(--info)]/5 text-[color:var(--info)]'
          : 'border-[color:var(--warning)]/30 bg-[color:var(--warning)]/5 text-[color:var(--warning)]',
      )}
    >
      {!loaded ? t('vulns.notLoaded') : t('vulns.stale')}
    </div>
  );
}
