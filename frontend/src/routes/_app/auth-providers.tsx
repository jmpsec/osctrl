import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { AuthProvidersPage } from '$/features/auth-providers/AuthProvidersPage';

export const authProvidersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'auth-providers',
  component: AuthProvidersPage,
});
