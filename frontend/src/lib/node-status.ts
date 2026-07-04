import { useQuery } from '@tanstack/react-query';
import { listServiceSettings, type SettingValue } from '$/api/settings';
import { isWithinHours } from '$/lib/time';

export const DEFAULT_INACTIVE_HOURS = 72;

function normalizeSettingName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function getInactiveHoursFromSettings(settings?: SettingValue[]): number {
  const match = settings?.find((setting) => normalizeSettingName(setting.Name) === 'inactivehours');
  if (!match || match.Type !== 'integer' || !Number.isFinite(match.Integer) || match.Integer <= 0) {
    return DEFAULT_INACTIVE_HOURS;
  }
  return match.Integer;
}

export function isNodeActive(lastSeen: string, inactiveHours = DEFAULT_INACTIVE_HOURS): boolean {
  return isWithinHours(lastSeen, inactiveHours);
}

export function useInactiveHours(): number {
  const { data } = useQuery({
    queryKey: ['settings', 'admin'],
    queryFn: () => listServiceSettings('admin'),
    staleTime: 30_000,
    retry: false,
  });

  return getInactiveHoursFromSettings(data);
}
