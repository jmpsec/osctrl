import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getVulnProfiles } from '$/api/vulnerabilities';
import type { PostureProfile } from '$/api/types';
import { ModalShell } from '$/components/feedback/ModalShell';
import { MetadataBadge } from '$/components/data/MetadataBadge';
import { Skeleton } from '$/components/data/Skeleton';

interface VulnProfilePickerProps {
  onPick: (profile: PostureProfile) => void;
  /** Must be stable (useCallback): ModalShell re-runs its focus effect on change. */
  onClose: () => void;
}

function platformLabel(platform: string): string {
  return platform === 'darwin' ? 'macOS' : platform.charAt(0).toUpperCase() + platform.slice(1);
}

/** The daily inventory schedules that feed vulnerability matching. */
export function VulnProfilePicker({ onPick, onClose }: VulnProfilePickerProps) {
  const { t } = useTranslation();
  const profiles = useQuery({
    queryKey: ['vuln-profiles'],
    queryFn: () => getVulnProfiles(),
    staleTime: 5 * 60_000,
    retry: 1,
  });
  return (
    <ModalShell
      title={t('vulns.profilesTitle')}
      titleId="vuln-profiles-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      <div className="space-y-3">
        {profiles.isLoading && <Skeleton className="h-20 w-full" />}
        {profiles.isError && (
          <div className="space-y-2 py-4 text-center">
            <p className="text-xs text-[color:var(--danger)]">{t('vulns.profilesLoadError')}</p>
            <button
              type="button"
              onClick={() => void profiles.refetch()}
              className="text-xs text-[color:var(--signal)] hover:underline"
            >
              {t('common.retry')}
            </button>
          </div>
        )}
        {profiles.isSuccess && profiles.data.length === 0 && (
          <p className="py-4 text-center text-xs text-[color:var(--text-3)]">{t('vulns.profilesEmpty')}</p>
        )}
        {(profiles.data ?? []).map((profile) => (
          <div key={profile.id} className="rounded-md border border-[color:var(--border)] p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[color:var(--text-1)]">{profile.name}</span>
                <MetadataBadge>{platformLabel(profile.platform)}</MetadataBadge>
              </div>
              <button
                type="button"
                onClick={() => onPick(profile)}
                aria-label={t('vulns.addProfileAria', { name: profile.name })}
                className="rounded px-2 py-1 text-xs font-medium text-[color:var(--signal)] transition-colors hover:bg-[color:var(--signal)]/10"
              >
                {t('vulns.addToSchedule')}
              </button>
            </div>
            <p className="mb-2 text-xs text-[color:var(--text-3)]">{profile.description}</p>
            <div className="flex flex-wrap gap-1">
              {Object.entries(profile.queries).map(([name, query]) => (
                <MetadataBadge key={name}>{query.query_name || name}</MetadataBadge>
              ))}
            </div>
          </div>
        ))}
      </div>
    </ModalShell>
  );
}
