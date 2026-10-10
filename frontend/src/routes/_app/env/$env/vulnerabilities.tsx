import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { VulnerabilitiesPage } from '$/features/vulnerabilities/VulnerabilitiesPage';
import { vulnSearchSchema } from '$/features/vulnerabilities/search';

export const envVulnerabilitiesRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'vulnerabilities',
  validateSearch: vulnSearchSchema,
  component: VulnerabilitiesPage,
});
