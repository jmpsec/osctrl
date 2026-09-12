import { afterEach, expect, it, vi } from 'vitest';
import { ApiError, AuthError } from './client';
import { EventParser, readEvents } from './events';

afterEach(() => vi.unstubAllGlobals());

it('parses split frames, CRLF, multiline JSON and heartbeat comments', () => {
  const receive = vi.fn();
  const parser = new EventParser(receive);
  parser.push(': heartbeat\n\nevent: resource.');
  parser.push('changed\r\ndata: {"name":\r\ndata: "café"}\r\n');
  expect(receive).not.toHaveBeenCalled();
  parser.push('\r\n');
  expect(receive).toHaveBeenCalledExactlyOnceWith({ event: 'resource.changed', data: { name: 'café' } });
});

it('ignores malformed JSON and bounds incomplete and complete frames', () => {
  const receive = vi.fn();
  const parser = new EventParser(receive);
  parser.push('data: not-json\n\n');
  expect(receive).not.toHaveBeenCalled();
  expect(() => parser.push('x'.repeat(8193))).toThrow('too large');
  expect(() => new EventParser(receive).push('data: '+ 'x'.repeat(8193)+'\n\n')).toThrow('too large');
});

it('exposes authentication and permission failures without interpreting HTML as events', async () => {
  const fetch = vi.fn().mockResolvedValue({ status: 401, ok: false });
  vi.stubGlobal('fetch', fetch);
  await expect(readEvents('dev', ['queries'], new AbortController().signal, vi.fn())).rejects.toBeInstanceOf(AuthError);
  fetch.mockResolvedValue({ status: 403, ok: false });
  await expect(readEvents('dev', ['queries'], new AbortController().signal, vi.fn())).rejects.toBeInstanceOf(ApiError);
  const [url, init] = fetch.mock.calls[0];
  expect(url).toBe('/api/v1/events?env=dev&topic=queries');
  expect(init.credentials).toBe('include');
  expect(init.headers).toEqual({ Accept: 'text/event-stream' });
});
