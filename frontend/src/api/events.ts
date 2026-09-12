import { ApiError, AuthError } from './client';

export type EventTopic = 'queries' | 'carves';
export interface StreamEvent { event: string; data: unknown }

// Fetch-based SSE exposes 401/403/429/503 to the caller. The JSON apiFetch
// wrapper intentionally remains unchanged for snapshots and mutations.
export async function readEvents(
  env: string,
  topics: EventTopic[],
  signal: AbortSignal,
  receive: (event: StreamEvent) => void,
): Promise<void> {
  const params = new URLSearchParams({ env });
  for (const topic of topics) params.append('topic', topic);
  const response = await fetch(`/api/v1/events?${params}`, {
    credentials: 'include', headers: { Accept: 'text/event-stream' }, signal,
  });
  if (response.status === 401) throw new AuthError();
  if (!response.ok) throw new ApiError('Live updates unavailable', response.status);
  if (!response.headers.get('Content-Type')?.startsWith('text/event-stream') || !response.body) {
    throw new ApiError('Invalid event stream', 502);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parser = new EventParser(receive);
  try {
    while (!signal.aborted) {
      const { value, done } = await reader.read();
      if (done) break;
      parser.push(decoder.decode(value, { stream: true }));
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

// Parses the LF/CRLF frames emitted by our API, including split UTF-8 chunks
// (decoded by readEvents), multiline data, and ignored heartbeat comments.
export class EventParser {
  private buffer = '';
  constructor(private receive: (event: StreamEvent) => void) {}

  push(chunk: string) {
    this.buffer += chunk;
    let boundary: RegExpExecArray | null;
    while ((boundary = /\r?\n\r?\n/.exec(this.buffer))) {
      const frame = this.buffer.slice(0, boundary.index);
      this.buffer = this.buffer.slice(boundary.index + boundary[0].length);
      if (frame.length > 8192) throw new Error('Event frame too large');
      let event = 'message';
      const data: string[] = [];
      for (const line of frame.split(/\r?\n/)) {
        if (line.startsWith(':')) continue;
        const colon = line.indexOf(':');
        const key = colon < 0 ? line : line.slice(0, colon);
        const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
        if (key === 'event') event = value;
        if (key === 'data') data.push(value);
      }
      if (!data.length) continue;
      let value: unknown;
      try { value = JSON.parse(data.join('\n')); } catch { continue; }
      this.receive({ event, data: value });
    }
    if (this.buffer.length > 8192) throw new Error('Event frame too large');
  }
}
