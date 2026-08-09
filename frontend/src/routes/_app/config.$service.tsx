import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { ServiceConfigPage } from '$/features/service-config/ServiceConfigPage';

export const serviceConfigRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'config/$service',
  component: ServiceConfigPage,
});
