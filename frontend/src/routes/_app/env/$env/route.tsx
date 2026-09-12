import { createRoute, Outlet, useParams } from '@tanstack/react-router';
import { LiveUpdatesProvider } from '$/lib/live-updates';
import { appRoute } from '$/routes/_app/route';

export const envRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'env/$env',
  component: function EnvLayout() {
    const { env } = useParams({ from: '/_app/env/$env' });
    return <LiveUpdatesProvider env={env}><Outlet /></LiveUpdatesProvider>;
  },
});
