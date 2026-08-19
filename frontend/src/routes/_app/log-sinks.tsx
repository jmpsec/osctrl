import { createRoute } from '@tanstack/react-router';
import { appRoute } from './route';
import { LogSinksPage } from '$/features/log-sinks/LogSinksPage';

export const logSinksRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'log-sinks',
  component: LogSinksPage,
});
