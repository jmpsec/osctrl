import { createRoute, redirect } from '@tanstack/react-router';
import { rootRoute } from './__root';
import { isAuthenticated } from '$/api/client';

export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad() {
    if (isAuthenticated()) {
      throw redirect({ to: '/_app' });
    }
    throw redirect({ to: '/login' });
  },
  // component is never rendered — beforeLoad always redirects
  component: () => null,
});
