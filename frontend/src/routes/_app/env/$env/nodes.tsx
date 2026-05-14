import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { NodesTablePage } from '$/features/nodes/NodesTablePage';

export const nodesSearchSchema = z.object({
  status: z.enum(['all', 'active', 'inactive']).optional(),
  q: z.string().optional(),
  sort: z
    .enum(['uuid', 'hostname', 'localname', 'ip', 'platform', 'version', 'osquery', 'lastseen', 'firstseen'])
    .optional(),
  dir: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().optional(),
  // Platform-bucket filter for the QuickFilters chip row. Empty means "all".
  platform: z.enum(['linux', 'darwin', 'windows', 'other']).optional(),
});

export const envNodesRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'nodes',
  validateSearch: nodesSearchSchema,
  component: NodesTablePage,
});
