import { apiFetch } from './client';
import type {
  FileExplorerEntry,
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
