import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { EnrollPage } from '$/features/enrollment/EnrollPage';

export const envEnrollRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'enroll',
  component: EnrollPage,
});
