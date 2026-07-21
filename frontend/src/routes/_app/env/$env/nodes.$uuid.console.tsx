import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { NodeConsolePage } from '$/features/nodes/NodeConsolePage';

export const envNodeConsoleRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'nodes/$uuid/console',
  component: NodeConsolePage,
});
