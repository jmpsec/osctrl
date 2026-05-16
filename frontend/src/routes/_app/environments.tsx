import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { EnvironmentsPage } from '$/features/environments/EnvironmentsPage';

export const environmentsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'environments',
  component: EnvironmentsPage,
});
