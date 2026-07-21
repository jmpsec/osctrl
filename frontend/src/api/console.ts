import { apiFetch } from './client';
import type {
  ConsoleCommand,
  ConsoleResultRow,
  ConsoleSession,
  ParsedConsoleCommand,
} from './types';

export function createConsoleSession(env: string, uuid: string): Promise<ConsoleSession> {
  return apiFetch<ConsoleSession>(
    `/api/v1/console/${encodeURIComponent(env)}/nodes/${encodeURIComponent(uuid)}/sessions`,
    { method: 'POST' },
  );
}

export function closeConsoleSession(env: string, sessionId: number): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(
    `/api/v1/console/${encodeURIComponent(env)}/sessions/${sessionId}`,
    { method: 'DELETE' },
  );
}

export function submitConsoleCommand(
  env: string,
  sessionId: number,
  input: string,
): Promise<{ command: ConsoleCommand; parsed: ParsedConsoleCommand }> {
  return apiFetch<{ command: ConsoleCommand; parsed: ParsedConsoleCommand }>(
    `/api/v1/console/${encodeURIComponent(env)}/sessions/${sessionId}/commands`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
    },
  );
}

export function getConsoleCommand(
  env: string,
  sessionId: number,
  commandId: number,
): Promise<ConsoleCommand> {
  return apiFetch<ConsoleCommand>(
    `/api/v1/console/${encodeURIComponent(env)}/sessions/${sessionId}/commands/${commandId}`,
  );
}

export function getConsoleCommandResults(
  env: string,
  sessionId: number,
  commandId: number,
): Promise<ConsoleResultRow[]> {
  return apiFetch<ConsoleResultRow[]>(
    `/api/v1/console/${encodeURIComponent(env)}/sessions/${sessionId}/commands/${commandId}/results`,
  );
}
