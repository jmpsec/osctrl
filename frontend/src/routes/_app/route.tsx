/**
 * /_app layout route — requires in-memory CSRF token.
 * If not authenticated, redirects to /login.
 */
import { createRoute, redirect, Outlet } from '@tanstack/react-router';
import { rootRoute } from '../__root';
import { AppShell } from '$/components/chrome/AppShell';
import { isAuthenticated } from '$/api/client';

export const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/_app',
  beforeLoad() {
    if (!isAuthenticated()) {
      throw redirect({ to: '/login' });
    }
  },
  component: function AppLayout() {
    return (
      <AppShell>
        <Outlet />
      </AppShell>
    );
  },
});
