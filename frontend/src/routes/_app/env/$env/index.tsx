import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { DashboardPage } from '$/features/dashboard/DashboardPage';

export const envIndexRoute = createRoute({
  getParentRoute: () => envRoute,
  path: '/',
  component: DashboardPage,
});
