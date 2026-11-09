import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { SantaPage } from '$/features/santa/SantaPage';

export const envSantaRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'santa',
  component: SantaPage,
});
