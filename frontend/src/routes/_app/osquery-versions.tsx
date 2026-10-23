import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { OsqueryVersionsPage } from '$/features/osquery-versions/OsqueryVersionsPage';

export const osqueryVersionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'osquery-versions',
  component: OsqueryVersionsPage,
});
