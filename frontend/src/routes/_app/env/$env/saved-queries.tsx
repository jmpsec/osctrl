import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { SavedQueriesPage } from '$/features/saved-queries/SavedQueriesPage';

export const savedQueriesSearchSchema = z.object({
  q: z.string().optional(),
  sort: z.enum(['name', 'creator', 'created', 'updated']).optional(),
  dir: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().max(500).optional(),
});

export const envSavedQueriesRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'saved-queries',
  validateSearch: savedQueriesSearchSchema,
  component: SavedQueriesPage,
});
