import { createRoute, redirect } from '@tanstack/react-router';
import { appRoute } from './route';
import { listEnvironments } from '$/api/environments';
import { isAuthenticated } from '$/api/client';
import { takeSantaRequestTarget } from '../santa.request.$env';

export const appIndexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  beforeLoad: async () => {
    if (!isAuthenticated()) {
      throw redirect({ to: '/login' });
    }
    // Every login lands here. A user who came from a Santa block dialog goes
    // back to the request they were about to make.
    const target = takeSantaRequestTarget();
    if (target) {
      throw redirect({
        to: '/santa/request/$env',
        params: { env: target.env },
        search: { sha256: target.sha256, machine_id: target.machine_id },
      });
    }
    // Redirect to the first environment's dashboard.
    const envs = await listEnvironments();
    const firstEnv = envs[0]?.name ?? 'dev';
    throw redirect({ to: '/_app/env/$env', params: { env: firstEnv } });
  },
  component: () => null,
});
