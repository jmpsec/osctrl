import type { ReactNode } from 'react';
import { Navigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { getFeatures } from '$/api/features';

/**
 * Single switch for every osctrld-dependent surface (extensions, node/env
 * flags overrides, osquery version pinning, osctrld status banners). Reads the
 * shared ['features'] query. Loading or error counts as disabled with
 * loaded=false, so guards can wait instead of flashing or redirecting.
 */
export function useOsctrldEnabled(): { enabled: boolean; loaded: boolean; failed: boolean } {
  const { data, isSuccess, isError } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  return { enabled: data?.osctrld === true, loaded: isSuccess, failed: isError };
}

/**
 * Route guard: nothing while features load (retries included), dashboard
 * redirect when osctrld is off or the features request failed.
 */
export function RequireOsctrld({ children }: { children: ReactNode }) {
  const { enabled, loaded, failed } = useOsctrldEnabled();
  if (!loaded && !failed) return null;
  if (!enabled) return <Navigate to="/_app" replace />;
  return <>{children}</>;
}
