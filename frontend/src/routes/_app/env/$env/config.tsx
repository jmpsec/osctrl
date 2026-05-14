import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { EnvConfigPage } from '$/features/environments/EnvConfigPage';

export const envConfigRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'config',
  component: EnvConfigPage,
});
