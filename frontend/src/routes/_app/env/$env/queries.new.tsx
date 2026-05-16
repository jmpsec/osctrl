import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { envRoute } from './route';
import { QueryRunPage } from '$/features/queries/QueryRunPage';

// Optional search params: `sql` prefills the editor (used by the Run link on
// the Saves page), `name` provides the source name for a small context label.
// Both are bounded — sql to 32 KiB so a malicious link can't blow up Monaco.
const queryNewSearchSchema = z.object({
  sql: z.string().max(32_768).optional(),
  name: z.string().max(256).optional(),
});

export type QueryNewSearch = z.infer<typeof queryNewSearchSchema>;

export const envQueryNewRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'queries/new',
  validateSearch: queryNewSearchSchema,
  component: QueryRunPage,
});
