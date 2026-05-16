import { createRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { appRoute } from './route';
import { AuditPage } from '$/features/audit/AuditPage';

export const auditSearchSchema = z.object({
  service: z.string().optional(),
  username: z.string().optional(),
  type: z.number().int().min(1).max(10).optional(),
  env_uuid: z.string().optional(),
  since: z.string().optional(),
  until: z.string().optional(),
  page: z.number().int().positive().optional(),
  page_size: z.number().int().positive().optional(),
});

export const auditRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'audit',
  validateSearch: auditSearchSchema,
  component: AuditPage,
});
