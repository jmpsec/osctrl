import { createRoute } from '@tanstack/react-router';
import { RequireOsctrld } from '$/lib/useOsctrldEnabled';
import { appRoute } from './route';
import { OsqueryVersionsPage } from '$/features/osquery-versions/OsqueryVersionsPage';

export const osqueryVersionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'osquery-versions',
  component: () => (
    <RequireOsctrld>
      <OsqueryVersionsPage />
    </RequireOsctrld>
  ),
});
