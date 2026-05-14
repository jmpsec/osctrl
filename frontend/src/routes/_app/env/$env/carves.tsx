import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { CarvesListPage } from '$/features/carves/CarvesListPage';

export const carvesSearchSchema = z.object({
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
  page_size: z.number().int().positive().max(500).optional(),
});

export const envCarvesRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'carves',
  validateSearch: carvesSearchSchema,
  component: CarvesListPage,
});
