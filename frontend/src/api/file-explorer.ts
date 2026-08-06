import { apiFetch } from './client';
import type {
  FileExplorerEntry,
  FileExplorerMetadataRow,
  FileExplorerRequest,
  FileExplorerSession,
  FileExplorerSessionResponse,
} from './types';

export function createFileExplorerSession(env: string, uuid: string): Promise<FileExplorerSessionResponse> {
  return apiFetch<FileExplorerSessionResponse>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/nodes/${encodeURIComponent(uuid)}/sessions`,
    { method: 'POST' },
  );
}

export function getFileExplorerSession(env: string, sessionId: number): Promise<FileExplorerSession> {
  return apiFetch<FileExplorerSession>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}`,
  );
}

export function closeFileExplorerSession(env: string, sessionId: number): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}`,
    { method: 'DELETE' },
  );
}

export function listFileExplorerDirectory(
  env: string,
  sessionId: number,
  path: string,
): Promise<FileExplorerRequest> {
  return submitFileExplorerPath(env, sessionId, 'list', path);
}

export function statFileExplorerPath(
  env: string,
  sessionId: number,
  path: string,
): Promise<FileExplorerRequest> {
  return submitFileExplorerPath(env, sessionId, 'stat', path);
}

export function getFileExplorerRequest(
  env: string,
  sessionId: number,
  requestId: number,
): Promise<FileExplorerRequest> {
  return apiFetch<FileExplorerRequest>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}/requests/${requestId}`,
  );
}

export function getFileExplorerRequestResults(
  env: string,
  sessionId: number,
  requestId: number,
): Promise<FileExplorerEntry[]> {
  return apiFetch<FileExplorerEntry[]>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}/requests/${requestId}/results`,
  );
}

/** Raw osquery_info row returned by the priming metadata request.
 *  Re-exported from ./types for callers that import from this module. */
export type { FileExplorerMetadataRow } from './types';

export function getFileExplorerPrimingMetadata(
  env: string,
  sessionId: number,
  requestId: number,
): Promise<FileExplorerMetadataRow[]> {
  return apiFetch<FileExplorerMetadataRow[]>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}/requests/${requestId}/metadata`,
  );
}

function submitFileExplorerPath(
  env: string,
  sessionId: number,
  action: 'list' | 'stat',
  path: string,
): Promise<FileExplorerRequest> {
  return apiFetch<FileExplorerRequest>(
    `/api/v1/file-explorer/${encodeURIComponent(env)}/sessions/${sessionId}/${action}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    },
  );
}
