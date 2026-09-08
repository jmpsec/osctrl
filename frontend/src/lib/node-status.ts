import { useQuery, type QueryClient } from '@tanstack/react-query';
import { getEnvironmentInactiveHours } from '$/api/environments';
import { isWithinHours } from '$/lib/time';

export function isNodeActive(lastSeen: string, inactiveHours: number | undefined): boolean | undefined {
  if (inactiveHours === undefined) return undefined;
  return isWithinHours(lastSeen, inactiveHours);
}

export function useInactiveHours(env: string) {
  return useQuery({
    queryKey: ['inactive-hours', env],
    queryFn: () => getEnvironmentInactiveHours(env),
    enabled: !!env,
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    retry: false,
  });
}

export function invalidateNodeStatusQueries(qc: QueryClient) {
  return Promise.all(['inactive-hours', 'nodes', 'node', 'stats'].map((key) =>
    qc.invalidateQueries({ queryKey: [key] }),
  ));
}
