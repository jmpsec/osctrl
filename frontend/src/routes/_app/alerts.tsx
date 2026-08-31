import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { AlertsPage } from '$/features/alerts/AlertsPage';

export const alertsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'alerts',
  component: AlertsPage,
});
