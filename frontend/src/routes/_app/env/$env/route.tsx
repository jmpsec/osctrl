import { createRoute, Outlet } from '@tanstack/react-router';
import { appRoute } from '$/routes/_app/route';

export const envRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'env/$env',
  component: function EnvLayout() {
    return <Outlet />;
  },
});
