import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { SettingsPage } from '$/features/settings/SettingsPage';

export const settingsServiceRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'settings/$service',
  component: SettingsPage,
});
