/**
 * Service config API client.
 *
 * Read-only access to the service_config table, which mirrors the structured
 * YAML configuration sections (logger, carver, SAML, OIDC, metrics, TLS, …)
 * per service into the database. Each section is stored as a JSON-encoded
 * blob. Phase 1 is read-only; phase 2 will add a PUT for editable sections.
 */
import { apiFetch } from './client';

/** Wire shape matching pkg/serviceconfig.ServiceConfig. */
export interface ServiceConfig {
  ID: number;
  CreatedAt: string;
  UpdatedAt: string;
  Name: string;
  Service: string;
  EnvironmentID: number;
  Type: string;
  Value: string;
  Source: string;
  Editable: boolean;
  Info: string;
}

/** GET /api/v1/service-config — all sections across all services. */
export function listAllServiceConfig(): Promise<ServiceConfig[]> {
  return apiFetch<ServiceConfig[]>('/api/v1/service-config');
}

/** GET /api/v1/service-config/{service} — all sections for one service. */
export function listServiceConfig(service: string): Promise<ServiceConfig[]> {
  return apiFetch<ServiceConfig[]>(
    `/api/v1/service-config/${encodeURIComponent(service)}`,
  );
}

/** GET /api/v1/service-config/{service}/{section} — one section. */
export function getServiceConfig(
  service: string,
  section: string,
): Promise<ServiceConfig> {
  return apiFetch<ServiceConfig>(
    `/api/v1/service-config/${encodeURIComponent(service)}/${encodeURIComponent(section)}`,
  );
}
