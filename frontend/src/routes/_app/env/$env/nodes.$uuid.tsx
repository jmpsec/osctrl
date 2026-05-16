import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { NodeDetailPage } from '$/features/nodes/NodeDetailPage';

export const envNodeDetailRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'nodes/$uuid',
  component: NodeDetailPage,
});
