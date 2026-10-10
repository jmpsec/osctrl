import { z } from 'zod';

/**
 * URL search params of the environment Vulnerabilities page. Filters and the
 * page live in the URL, not component state, so Back returns to the same
 * view and switching environment (which drops the search) starts fresh.
 * A malformed value falls back to its default instead of failing the route.
 */
export const vulnSearchSchema = z.object({
  severity: z.enum(['critical', 'high', 'medium', 'low', 'unknown']).optional().catch(undefined),
  state: z.enum(['open', 'resolved', 'all']).optional().catch(undefined),
  kev: z.boolean().optional().catch(undefined),
  page: z.number().int().positive().optional().catch(undefined),
});

export type VulnSearch = z.infer<typeof vulnSearchSchema>;
