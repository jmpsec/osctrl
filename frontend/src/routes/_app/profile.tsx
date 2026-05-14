import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { ProfilePage } from '$/features/profile/ProfilePage';

export const profileRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'profile',
  component: ProfilePage,
});
