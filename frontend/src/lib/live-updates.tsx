import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { ApiError, AuthError, setCsrfToken } from '$/api/client';
import { readEvents, type EventTopic, type StreamEvent } from '$/api/events';
import { getFeatures } from '$/api/features';

type Register = (topic: EventTopic) => () => void;
const LiveUpdatesContext = createContext<Register | null>(null);

// Coalesces invalidations and performs a trailing refetch if an event arrives
// while a snapshot is in flight. It never patches authoritative result rows.
export function createInvalidator(client: QueryClient, env: string) {
  const pending = new Map<string, { topic: EventTopic; name?: string }>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let active = true;
  let running = false;
  const schedule = () => {
    if (active && !running && !timer) timer = setTimeout(() => { void flush(); }, 250);
  };
  const flush = async () => {
    timer = undefined;
    if (!active || running) return;
    running = true;
    const batch = [...pending.values()];
    pending.clear();
    try {
      const requests = batch.flatMap(({ topic, name }) => {
        const keys = topic === 'queries' ? ['queries', 'query', 'query-results'] : ['carves', 'carve'];
        return keys.map(async key => {
          const filters = { queryKey: name && key !== topic ? [key, env, name] : [key, env] };
          const wasFetching = client.isFetching(filters) > 0;
          await client.invalidateQueries(filters, { cancelRefetch: false });
          if (active && wasFetching) await client.invalidateQueries(filters, { cancelRefetch: false });
        });
      });
      await Promise.allSettled(requests);
    } finally {
      running = false;
      if (pending.size) schedule();
    }
  };
  return {
    add(topic: EventTopic, name?: string) {
      if (!active) return;
      if (!name || pending.size >= 64) {
        for (const [key, item] of pending) if (item.topic === topic) pending.delete(key);
        pending.set(topic, { topic });
      } else if (!pending.has(topic)) pending.set(`${topic}:${name}`, { topic, name });
      schedule();
    },
    close() { active = false; pending.clear(); if (timer) clearTimeout(timer); },
  };
}

export function LiveUpdatesProvider({ env, children }: { env: string; children: ReactNode }) {
  const client = useQueryClient();
  const [counts, setCounts] = useState<Record<EventTopic, number>>({ queries: 0, carves: 0 });
  const register = useCallback<Register>((topic) => {
    setCounts(current => ({ ...current, [topic]: current[topic] + 1 }));
    return () => setCounts(current => ({ ...current, [topic]: Math.max(0, current[topic] - 1) }));
  }, []);
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const selection = (Object.keys(counts) as EventTopic[])
    .filter(topic => counts[topic] > 0 && features?.event_topics?.includes(topic)).sort().join(',');

  useEffect(() => {
    if (!features?.events || !selection) return;
    const topics = selection.split(',') as EventTopic[];
    const invalidator = createInvalidator(client, env);
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let environmentUUID: string | undefined;
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
        // Permissions can change while the login is still valid. Refresh the
        // current view through REST so its existing 401/403 behavior applies.
        for (const topic of topics) invalidator.add(topic);
      } else if (event === 'stream.ready' && typeof value.environment_uuid === 'string') {
        environmentUUID = value.environment_uuid;
        attempts = 0;
        for (const topic of topics) invalidator.add(topic);
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        environmentUUID && value.environment_uuid === environmentUUID &&
        topics.includes(value.topic as EventTopic) && typeof value.name === 'string' && value.name.length <= 256) {
        invalidator.add(value.topic as EventTopic, value.name);
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      environmentUUID = undefined;
      controller = new AbortController();
      try { await readEvents(env, topics, controller.signal, receive); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
          for (const topic of topics) invalidator.add(topic);
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); invalidator.close(); };
  }, [client, env, features?.events, selection]);

  return <LiveUpdatesContext.Provider value={register}>{children}</LiveUpdatesContext.Provider>;
}

// Existing polling stays enabled during the initial mixed-version rollout.
export function useResourceUpdates(topic: EventTopic) {
  const register = useContext(LiveUpdatesContext);
  useEffect(() => register?.(topic), [register, topic]);
}
