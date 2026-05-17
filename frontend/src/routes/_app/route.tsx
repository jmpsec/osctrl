/**
 * /_app layout route — requires in-memory CSRF token.
 * If not authenticated, redirects to /login.
 */
import { createRoute, redirect, Outlet } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { rootRoute } from '../__root';
import { AppShell } from '$/components/chrome/AppShell';
import { isAuthenticated } from '$/api/client';
import { getMe } from '$/api/users';

export const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/_app',
  beforeLoad() {
    if (!isAuthenticated()) {
      throw redirect({ to: '/login' });
    }
  },
  component: function AppLayout() {
    // Resolve the actual authenticated user via /api/v1/users/me so
    // the avatar + Sign-Out menu reflect WHO is logged in. Without
    // this fetch, AppShell received no username and UserMenu fell
    // back to its hardcoded 'admin' default — fine for a single-
    // operator dev install, misleading once OIDC introduced a
    // second identity (alice). staleTime keeps the result for the
    // session so we don't refetch on every route change.
    const { data: me } = useQuery({
      queryKey: ['users-me'],
      queryFn: () => getMe(),
      staleTime: 5 * 60_000,
      retry: 1,
    });
    return (
      <AppShell username={me?.username}>
        <Outlet />
      </AppShell>
    );
  },
});
