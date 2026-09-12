import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { ApiError, AuthError, setCsrfToken } from '$/api/client';
import { readEvents, type EventTopic, type StreamEvent } from '$/api/events';
import { getFeatures } from '$/api/features';

type Register = (topic: EventTopic) => () => void;
type LiveStatus = {
  register: Register;
  live: Record<EventTopic, boolean>;
};
const LiveUpdatesContext = createContext<LiveStatus | null>(null);
const fallbackRefetchInterval = 15_000;
const liveReconcileInterval = 60_000;
type ChangeKind = 'metadata' | 'results' | 'files';
type PendingInvalidation = { topic: EventTopic; name?: string; change?: ChangeKind };

function invalidationKeys(topic: EventTopic, change?: ChangeKind) {
  if (topic === 'queries') {
    if (change === 'metadata') return ['queries', 'query'];
    if (change === 'results') return ['query-results'];
    return ['queries', 'query', 'query-results'];
  }
  if (change === 'metadata') return ['carves', 'carve'];
  if (change === 'files') return ['carve', 'carves'];
  return ['carves', 'carve'];
}

// Coalesces invalidations and performs a trailing refetch if an event arrives
// while a snapshot is in flight. It never patches authoritative result rows.
export function createInvalidator(client: QueryClient, env: string) {
  const pending = new Map<string, PendingInvalidation>();
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
      const requests = batch.flatMap(({ topic, name, change }) => {
        const keys = invalidationKeys(topic, change);
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
    add(topic: EventTopic, name?: string, change?: ChangeKind) {
      if (!active) return;
      if (!name || pending.size >= 64) {
        for (const [key, item] of pending) if (item.topic === topic) pending.delete(key);
        pending.set(topic, { topic });
      } else if (!pending.has(topic)) pending.set(`${topic}:${change || 'all'}:${name}`, { topic, name, change });
      schedule();
    },
    close() { active = false; pending.clear(); if (timer) clearTimeout(timer); },
  };
}

export function LiveUpdatesProvider({ env, children }: { env: string; children: ReactNode }) {
  const client = useQueryClient();
  const [counts, setCounts] = useState<Record<EventTopic, number>>({ queries: 0, carves: 0 });
  const [live, setLive] = useState<Record<EventTopic, boolean>>({ queries: false, carves: false });
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
    const setTopicsLive = (value: boolean) => {
      setLive(current => {
        const next = { ...current };
        for (const topic of topics) next[topic] = value;
        return next;
      });
    };
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
        setTopicsLive(true);
        for (const topic of topics) invalidator.add(topic);
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        environmentUUID && value.environment_uuid === environmentUUID &&
        topics.includes(value.topic as EventTopic) && typeof value.name === 'string' && value.name.length <= 256) {
        const change = value.change === 'metadata' || value.change === 'results' || value.change === 'files' ? value.change : undefined;
        invalidator.add(value.topic as EventTopic, value.name, change);
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
      if (active) setTopicsLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); invalidator.close(); setTopicsLive(false); };
  }, [client, env, features?.events, selection]);

  const value = useMemo(() => ({ register, live }), [register, live]);
  return <LiveUpdatesContext.Provider value={value}>{children}</LiveUpdatesContext.Provider>;
}

export function resourceRefetchInterval(
  live: boolean,
  resource?: { active?: boolean; completed?: boolean; expired?: boolean; deleted?: boolean },
) {
  if (resource && (!resource.active || resource.completed || resource.expired || resource.deleted)) {
    return false;
  }
  return live ? liveReconcileInterval : fallbackRefetchInterval;
}

export function useResourceUpdates(topic: EventTopic) {
  const status = useContext(LiveUpdatesContext);
  useEffect(() => status?.register(topic), [status?.register, topic]);
  return status?.live[topic] ?? false;
}
