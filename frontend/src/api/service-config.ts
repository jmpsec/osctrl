/**
 * Service config API client.
 *
 * Access to the service_config table, which mirrors the structured YAML
 * configuration sections (logger, carver, SAML, OIDC, metrics, TLS, …) per
 * service into the database. Each section is stored as a JSON-encoded blob.
 * Read endpoints are available for all sections; editable sections can be
 * updated via PUT.
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

/** Body shape for PUT /api/v1/service-config/{service}/{section}. */
export interface ServiceConfigUpdateRequest {
  /** Raw JSON object representing the new section contents. */
  value: unknown;
}

/** PUT /api/v1/service-config/{service}/{section} — update an editable section. */
export function updateServiceConfig(
  service: string,
  section: string,
  body: ServiceConfigUpdateRequest,
): Promise<ServiceConfig> {
  return apiFetch<ServiceConfig>(
    `/api/v1/service-config/${encodeURIComponent(service)}/${encodeURIComponent(section)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

export interface ServiceCommand {
  command_id: string;
  target_service: string;
  action: string;
  status: 'pending' | 'consumed' | 'recovered' | 'expired';
  requested_by?: string;
  requested_from?: string;
  created_at?: string;
  expires_at?: string;
  consumed_at?: string;
  consumed_by?: string;
  recovered_at?: string;
  recovered_by?: string;
}

export interface ServiceConfigApplyResponse {
  message: string;
  service?: string;
  command?: ServiceCommand;
}

/** POST /api/v1/service-config/apply — trigger graceful restart to apply config changes. */
export function applyServiceConfig(service = 'api'): Promise<ServiceConfigApplyResponse> {
  return apiFetch<ServiceConfigApplyResponse>('/api/v1/service-config/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ service }),
  });
}

export interface ServiceConfigStatus {
  service: string;
  /** Sections edited in the DB that the YAML file on disk does not have. */
  pending_changes: boolean;
  file_path: string;
  /** Whether the service's own process can write its config file. */
  file_writable: boolean;
  /** Why the file cannot be written, when file_writable is false. */
  file_reason?: string;
  checked_at?: string;
}

/** GET /api/v1/service-config/status/{service} — unsaved changes + file writability. */
export function getServiceConfigStatus(service: string): Promise<ServiceConfigStatus> {
  return apiFetch<ServiceConfigStatus>(
    `/api/v1/service-config/status/${encodeURIComponent(service)}`,
  );
}

export interface ServiceConfigPersistResponse {
  message: string;
  service?: string;
  /** Present for osctrl-tls, which performs the write in its own process. */
  command?: ServiceCommand;
}

/** POST /api/v1/service-config/persist — write DB changes back to the YAML file. */
export function persistServiceConfig(
  service = 'api',
): Promise<ServiceConfigPersistResponse> {
  return apiFetch<ServiceConfigPersistResponse>('/api/v1/service-config/persist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ service }),
  });
}

/** GET /api/v1/service-config/commands/{command_id} — command restart status. */
export function getServiceCommand(commandID: string): Promise<ServiceCommand> {
  return apiFetch<ServiceCommand>(
    `/api/v1/service-config/commands/${encodeURIComponent(commandID)}`,
  );
}
