import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { QueriesListPage } from '$/features/queries/QueriesListPage';

export const queriesSearchSchema = z.object({
  target: z
    .enum([
      'all',
      'all-full',
      'active',
      'completed',
      'expired',
      'saved',
      'hidden-completed',
      'deleted',
      'hidden',
    ])
    .optional(),
  q: z.string().optional(),
  sort: z
    .enum(['name', 'creator', 'created', 'type', 'expected', 'executions', 'errors'])
    .optional(),
  dir: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().optional(),
});

export const envQueriesRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'queries',
  validateSearch: queriesSearchSchema,
  component: QueriesListPage,
});
