import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { ExtensionsPage } from '$/features/extensions/ExtensionsPage';

export const extensionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'extensions',
  component: ExtensionsPage,
});
