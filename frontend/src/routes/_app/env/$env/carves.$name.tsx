import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { CarveDetailPage } from '$/features/carves/CarveDetailPage';

export const envCarveDetailRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'carves/$name',
  component: CarveDetailPage,
});
