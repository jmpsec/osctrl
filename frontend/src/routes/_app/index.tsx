import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { DashboardPage } from '$/features/dashboard/DashboardPage';

export const appIndexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  component: DashboardPage,
});
