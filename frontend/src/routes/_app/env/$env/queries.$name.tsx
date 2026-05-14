import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { QueryDetailPage } from '$/features/queries/QueryDetailPage';

export const queryDetailSearchSchema = z.object({
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().max(1000).optional(),
  since: z.string().optional(),
});

export const envQueryDetailRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'queries/$name',
  validateSearch: queryDetailSearchSchema,
  component: QueryDetailPage,
});
