import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { HealthPage } from '$/features/health/HealthPage';

export const healthRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'health',
  component: HealthPage,
});
