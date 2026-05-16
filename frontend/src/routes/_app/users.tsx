import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { UsersPage } from '$/features/users/UsersPage';

export const usersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'users',
  component: UsersPage,
});
