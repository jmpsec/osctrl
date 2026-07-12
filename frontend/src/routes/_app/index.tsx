import { createRoute, redirect } from '@tanstack/react-router';
import { appRoute } from './route';
import { listEnvironments } from '$/api/environments';
import { isAuthenticated } from '$/api/client';

export const appIndexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  beforeLoad: async () => {
    if (!isAuthenticated()) {
      throw redirect({ to: '/login' });
    }
    // Redirect to the first environment's dashboard.
    const envs = await listEnvironments();
    const firstEnv = envs[0]?.name ?? 'dev';
    throw redirect({ to: '/_app/env/$env', params: { env: firstEnv } });
  },
  component: () => null,
});
