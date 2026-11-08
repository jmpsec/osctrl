import { useQuery } from '@tanstack/react-query';
import { getMe } from '$/api/users';

// Shares the ['users-me'] cache entry with the existing inline consumers.
export function useMe() {
  return useQuery({ queryKey: ['users-me'], queryFn: () => getMe(), staleTime: 5 * 60_000 });
}
