import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { CarveRunPage } from '$/features/carves/CarveRunPage';

export const envCarveNewRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'carves/new',
  component: CarveRunPage,
});
